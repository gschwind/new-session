/*

Copyright (2021) Benoit Gschwind <gschwind@gnu-log.net>

new-session is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#include <linux/vt.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <termios.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <iostream>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <cstring>
#include <vector>

using namespace std;

// A basic pam conversational function, basicaly prompt in stdout and read on stdin
static int conv(int num_msg, pam_message const ** msg, pam_response ** response, void * data)
{

	termios tc;
	tcgetattr(STDIN_FILENO, &tc);

	*response = reinterpret_cast<pam_response *>(calloc(num_msg, sizeof(pam_response)));

	for (int i = 0; i < num_msg; ++i) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF: {
			termios tcx = tc;
			tcx.c_lflag = ~(ICANON | ECHO);
			tcsetattr(STDIN_FILENO, TCSANOW, &tcx);
			cout << msg[i]->msg << endl;
			std::string r;
			std::cin >> r;
			(*response)[i].resp = strdup(r.c_str());
			tcsetattr(STDIN_FILENO, TCSANOW, &tc);
		}
		break;
		case PAM_PROMPT_ECHO_ON: {
			termios tcx = tc;
			tcx.c_lflag = (ICANON | ECHO);
			tcsetattr(STDIN_FILENO, TCSANOW, &tcx);
			cout << msg[i]->msg << endl;
			std::string r;
			std::cin >> r;
			(*response)[i].resp = strdup(r.c_str());
			tcsetattr(STDIN_FILENO, TCSANOW, &tc);
		}
		break;
		case PAM_ERROR_MSG: {
			cerr << "ERROR: " << msg[i]->msg << endl;
		}
		break;
		case PAM_TEXT_INFO: {
			cout << "INFO: " << msg[i]->msg << endl;
		}
		break;
		}

	}

	return PAM_SUCCESS;

}

int main(int argc, char ** argv)
{
	char buf[256];

	// Clear all current suplementary group, as root we do not need anny of them.
	// Later it will prevent that root groups leak to the user session.
	if (setgroups(0, NULL) < 0) {
		cerr << "Failled to drop suplementary groups" << endl;
		exit(EXIT_FAILURE);
	}

	{
		// We put our PID in the /sys/fs/cgroup/cgroup.procs to escape current session cgroup
		// If we do not do that systemd-login will not create a new session
		int cgfd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
		if (cgfd < 0) {
			cerr << "Could not open `/sys/fs/cgroup/cgroup.procs`" << endl;
			exit(EXIT_FAILURE);
		}

		snprintf(buf, 256, "%d\n", getpid());
		if (write(cgfd, buf, strlen(buf)) != strlen(buf)) {
			cerr << "Could not move ourself in /sys/fs/cgroup/cgroup.procs" << endl;
			exit(EXIT_FAILURE);
		}
		close(cgfd);
	}



	int st;
	pam_conv const pam_conversation {
		&conv,
		nullptr
	};

	pam_handle_t * pamh;

	// Starting the PAM interaction, select the common system-login,
	// maybe null could also do the job, because it should fallback to the system default.
	// The second parameter is an user name, using nullptr tell pam to ask for an user name.
	st = pam_start("system-login", nullptr, &pam_conversation, &pamh);
	if (st != PAM_SUCCESS) {
		cerr << "pam_start ERROR" << endl;
		exit(EXIT_FAILURE);
	}

	// This is not well documented in PAM, but basicality the
	// pam_authenticate will run rules of type "auth" for the
	// selected service, in our case "system-login"
	// Rule may require user input, such input will be handled with the conv
	// function above.
	st = pam_authenticate(pamh, 0);
	if (st != PAM_SUCCESS) {
		cerr << "pam_authenticate ERROR" << endl;
		exit(EXIT_FAILURE);
	}

	void const * user_name;

	// Because we did not specified an user name we ask pam to give us what the user provided.
	st = pam_get_item(pamh, PAM_USER, &user_name);
	if (st != PAM_SUCCESS) {
		cerr << "Get pam user name failed" << endl;
		exit(EXIT_FAILURE);
	}

	// Get user details such as uid and gid to setup the user environnement.
	auto pw = getpwnam(reinterpret_cast<char const *>(user_name));
	if (!pw) {
		cerr << "Get user details failled" << endl;
		exit(EXIT_FAILURE);
	}

	// Setup some missing environnment variable, within the internal pam environnment.
	// The pam environnment will be used latter as user environnment.
	snprintf(buf, 256, "USER=%s", reinterpret_cast<char const *>(user_name));
	pam_putenv(pamh, buf);
	snprintf(buf, 256, "HOME=%s", pw->pw_dir);
	pam_putenv(pamh, buf);

	// It is not clear what this will do exactly and why it is here
	// between pam_authenticate and pam_acct_mgmt.
	st = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (st != PAM_SUCCESS) {
		cerr << "pam_setcred ERROR" << endl;
		exit(EXIT_FAILURE);
	}

	// Not well documented in PAM, imo. basically will apply rule of type "account" for the
	// selected service
	st = pam_acct_mgmt(pamh, 0);
	if (st != PAM_SUCCESS) {
		cerr << "pam_acct_mgmt ERROR" << endl;
		exit(EXIT_FAILURE);
	}

	// Now we have done the authantification procedure, we will fork to setup an spawn the new user
	// session and process.
	// First fork, the main process will juste wait for the termination of it child while the child
	// Will finalise the user environnement and will exec the expected process
	int pid = fork();
	if (pid == 0) {
		// We are in the child process

		// First go to the user home dir
		if (chdir(pw->pw_dir) < 0) {
			cerr << "Faild to go in user home dir:" << strerror(errno) << endl;
			exit(EXIT_FAILURE);
		}

		// Open the master VitualTerminal (VT) to lookup the current state of VTs
		int fd = open("/dev/tty0", O_RDWR | O_NOCTTY);
		if (fd < 0) {
			cerr << "Failed to open VT master:" << strerror(errno) << endl;
			exit(EXIT_FAILURE);
		}

		// Get the current state, not used yet.
		vt_stat vtState = { 0 };
		if (ioctl(fd, VT_GETSTATE, &vtState) < 0) {
			cout << "Failed to get current VT:" << strerror(errno) << endl;
			close(fd);
			exit(EXIT_FAILURE);
		}

		// Query for a new unused TTY
		// FIXME: This VTs selection have weard interraction with gdm.
		// GDM discard itself from VT when the VT is not the current master (i.e. is not the current shown VT)
		// and it take back the control of his VT without care, kicking the current user of it. Thus this query will
		// provide the GDM VT ...
		int vt = 0;
		if (ioctl(fd, VT_OPENQRY, &vt) < 0) {
			cerr << "Failed to open new VT:" << strerror(errno) << endl;
			close(fd);
			exit(EXIT_FAILURE);
		}

		// Ensure that the regular can read/write to the selected VT
		snprintf(buf, 256, "/dev/tty%d", vt);
		if (chown(buf, pw->pw_uid, -1) < 0) {
			cerr << "Fail to change TTY owner:" << strerror(errno) << endl;
			exit(EXIT_FAILURE);
		}

		// Open our VTs to setup stdin, stdout and stderr
		cout << "Open: " << buf << endl;
		int tty = open(buf, O_RDWR);
		if (tty < 0) {
			cerr << "Failed to open TTY:" << strerror(errno) << endl;
			exit(EXIT_FAILURE);
		}

		// Setup stdin, stdout and stderr
		dup2(tty, STDIN_FILENO);

		// On normal setup we should setup stdout and seterr as follow,
		// But in our case we want to keep outputs in current TTY
		// TODO: maybe implement a tee style fork of those
		//dup2(tty, STDOUT_FILENO);
		//dup2(tty, STDERR_FILENO);

		// Close remanant files
		close(tty);
		close(fd);

		// There is several session in linux, here we take the leadership the process session.
		// Some more detail in man credentials
		if (setsid() < 0) {
			cerr << "Failed to get session leadership:" << strerror(errno) << endl;
			exit(EXIT_FAILURE);
		}

		// Explicitly take the tty control
		// Note that following the documentation, the open above should be enough.
		if (ioctl(STDIN_FILENO, TIOCSCTTY) < 0) {
                    cerr << "Failed to take control of the tty:" << strerror(errno) << endl;
                    exit(EXIT_FAILURE);
                }

		// Tell pam that we have a fresh TTY.
		pam_set_item(pamh, PAM_TTY, buf);

		// Setup mandatory environnement variable that will be used by the pam module "systemd_login"
		// TODO: do better XDG_SEAT selection, here we hardcode the default seat i.e. "seat0", which is the actual
		// standard default.
		snprintf(buf, 256, "XDG_SEAT=seat0");
		pam_putenv(pamh, buf);

		// Tell to system which VT we will use
		snprintf(buf, 256, "XDG_VTNR=%d", vt);
		pam_putenv(pamh, buf);

		// Some descent parameters default
		// TODO: maybe use env variable or implement some way to change it.
		pam_putenv(pamh, "XDG_SESSION_CLASS=user");
		pam_putenv(pamh, "XDG_SESSION_TYPE=wayland");
		pam_putenv(pamh, "XDG_SESSION_DESKTOP=new-session");

		// Here we run trough pam rule of type "session"
		// The rules should call the systemd_login module and set a new fresh
		// using environnment above
		// systemd-login session. You can check it via loginctl
		st = pam_open_session(pamh, 0);
		if (st != PAM_SUCCESS) {
			cerr << "pam_open_session ERROR" << endl;
			exit(EXIT_FAILURE);
		}

		cout << "Session openned" << endl;

		// Now we have finished with the setup of the environnment and
		// we will swith to regular user right.

		// Set the GID
		if (setgid(pw->pw_gid) < 0) {
			cerr << "Failed to set GID" << endl;
			exit(EXIT_FAILURE);
		}


		// fetch ambient groups from PAM's environment;
		// these are set by modules such as pam_groups.so
		vector<gid_t> pam_groups;
		int n_pam_groups = getgroups(0, NULL);
		if (n_pam_groups > 0) {
			pam_groups.resize(n_pam_groups);
			if ((getgroups(n_pam_groups, &pam_groups[0])) == -1) {
				cout << "getgroups() failed to fetch supplemental" << "PAM groups for user:" << user_name << endl;
				exit(EXIT_FAILURE);
			}
		}

		// fetch session's user's groups
		vector<gid_t> user_groups;
		int n_user_groups = 0;
		if (-1 == getgrouplist(pw->pw_name, pw->pw_gid, NULL, &n_user_groups)) {
			user_groups.resize(n_user_groups);
			if ((getgrouplist(pw->pw_name, pw->pw_gid, &user_groups[0], &n_user_groups)) == -1 ) {
				cerr << "getgrouplist(" << pw->pw_name << ", " << pw->pw_gid << ") failed" << endl;
				exit(EXIT_FAILURE);
			}
		}

		// Set the suplementary group from gathered groups
		vector<gid_t> groups = pam_groups;
		groups.insert(groups.end(), user_groups.begin(), user_groups.end());
		if (groups.size() > 0) {
			if (setgroups(groups.size(), &groups[0]) != 0) {
				cerr << "setgroups() failed for user: " << user_name << endl;
				exit(EXIT_FAILURE);
			}
		}

		// Actually leaving the root user for the target user
		if (setuid(pw->pw_uid) < 0) {
			cerr << "Failed to set UID" << endl;
			exit(EXIT_FAILURE);
		}

		// Replacing current process by the one process requested by the user
		// using the pam environnment.
		// Use argc+1 to copy the last nullptr
		vector<char *> args(&argv[1], &argv[argc+1]);
		execvpe(args[0], &args[0], pam_getenvlist(pamh));

		// Gardian exit, should not be reach if the above exec have succeed.
		exit(EXIT_FAILURE);
	}


	// Parent process
	// Wait until the child died
	int rt;
	wait(&rt);

	// Close the session. It's not clear what going here.
	st = pam_close_session(pamh, 0);
	if (st != PAM_SUCCESS) {
		cerr << "pam_close_session ERROR" << endl;
		exit(EXIT_FAILURE);
	}

	// Free data used by PAM, maybe we can do that earlyer.
	st = pam_end(pamh, st);
	if (st != PAM_SUCCESS) {
		cerr << "pam_end ERROR" << endl;
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

