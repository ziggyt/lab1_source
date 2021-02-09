/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

#define LINE_BUFFER_LENGTH  1000


void sighandler() {

    /* add signalhandling routines here */
    /* see 'man 2 signal' */

    signal(SIGINT, SIG_IGN);
    signal(SIGKILL, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
}

int main(int argc, char *argv[]) {

//	passwd *passwddata; /* this has to be redefined in step 2 */
    /* see pwent.h */

    mypwent *passwddata;

    char important1[LENGTH] = "**IMPORTANT 1**";

    char user[LENGTH];

    char important2[LENGTH] = "**IMPORTANT 2**";

    //char   *c_pass; //you might want to use this variable later...
    char prompt[] = "password: ";
    char *user_pass;

    sighandler();

    while (TRUE) {

        /* check what important variable contains - do not remove, part of buffer overflow test */
        printf("Value of variable 'important1' before input of login name: %s\n",
               important1);
        printf("Value of variable 'important2' before input of login name: %s\n",
               important2);

        printf("login: ");
        fflush(NULL); /* Flush all  output buffers */
        __fpurge(stdin); /* Purge any data in stdin buffer */

        char *res = fgets(user, LENGTH, stdin);
//        res[sizeof(res)-1] = '\0';  //fix according to lab pm 4.1.3

        user[strcspn(user, "\n")] = '\0';

//        printf("%s", user);


        if (res == NULL) /* gets() is vulnerable to buffer */
            exit(0); /*  overflow attacks.  */

        /* check to see if important variable is intact after input of login name - do not remove */
        printf("Value of variable 'important 1' after input of login name: %*.*s\n",
               LENGTH - 1, LENGTH - 1, important1);
        printf("Value of variable 'important 2' after input of login name: %*.*s\n",
               LENGTH - 1, LENGTH - 1, important2);

        user_pass = getpass(prompt);
        passwddata = mygetpwnam(user);

        if (passwddata != NULL) {
            /* You have to encrypt user_pass for this to work */
            /* Don't forget to include the salt */

            if (passwddata->pwfailed >= 10) {
                printf("Too many failed login attempts, exiting\n");
                break;
            }
            char *salted_passwd = crypt(user_pass, passwddata->passwd_salt);

            if (!strcmp(salted_passwd, passwddata->passwd)) { //  pw_passwd to passwd

                printf("You're in !\n");
                printf("Previous login attempts: ");
                printf("%d", passwddata->pwfailed);
                printf("\n");

                passwddata->pwage++; //todo make 0 after pw change
                passwddata->pwfailed = 0;
                mysetpwent(passwddata->pwname, passwddata);

                if (passwddata->pwage >= 10) {
                    printf("You've used your password too many times, please update it! \n");
                    printf("Enter new password: ");

                    char new_password[LINE_BUFFER_LENGTH];
                    fgets(new_password, LINE_BUFFER_LENGTH, stdin);

                    printf("Please confirm new password: ");

                    char new_password_conf[LINE_BUFFER_LENGTH];
                    fgets(new_password_conf, LINE_BUFFER_LENGTH, stdin);


                    if (!strcmp(new_password, new_password_conf)) {
                        printf("%s\n", "Password updated!");

                        new_password[strcspn(new_password, "\n")] = '\0';
                        passwddata->passwd = crypt(new_password, passwddata->passwd_salt);
                        passwddata->pwage = 0;

                        mysetpwent(passwddata->pwname, passwddata);

                    } else {
                        printf("%s\n", "Could not update password");
                    }

                }

                /*  check UID, see setuid(2) */
                /*  start a shell, use execve(2) */ //used system instead

                setuid(passwddata->uid);
                //printf("%d", getuid());
                system((const char *) "/bin/sh");

            } else {

                printf("Login Incorrect \n");
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);

            }
        }
    }
    return 0;
}
