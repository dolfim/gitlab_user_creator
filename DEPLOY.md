# Deployment

In our setup we deployed this tool on the same server running the Omnibus package of GitLab.

Let assume:

* We deploy on Ubuntu 14.04.
* The app will run as user ```gitlab_user_creator``` with home ```/webapps/gitlab_user_creator``` with group ```webapps```.
* We use [Gunicorn](http://gunicorn.org) as a WSGI server, which is controlled via [Supervisor](http://supervisord.org).
* We use the built-in Nginx service provided in [GitLab Omnibus](http://doc.gitlab.com/omnibus/).
* The application will be served as [https://gitlabhost/myapps/external_user]().

## Application user

```bash
sudo groupadd webapps
sudo useradd --gid webapps --shell /bin/bash --home /webapps/gitlab_user_creator gitlab_user_creator
usermod -a -G webapps gitlab-www
sudo mkdir -p /webapps/gitlab_user_creator/
sudo chown gitlab_user_creator /webapps/gitlab_user_creator/
```

## Install required packages

System packages
```bash
sudo apt-get install python-virtualenv virtualenv supervisor
```

Create and start virtualenv
```bash
sudo su - gitlab_user_creator
cd /webapps/gitlab_user_creator/
virtualenv venv
source venv/bin/activate
pip install -U gunicorn
```

## Clone this repo

Make sure to clone this repo in ```/webapps/gitlab_user_creator/app``` and configure the ```settings.cfg``` file as explained in [README](README.md).

In ```settings.cfg``` you need the following parameter for the correct behavior of the reverse proxy:
```
APPLICATION_ROOT = '/myapps/external_user'
```

## Setup Gunicorn

Content of file ```/webapps/gitlab_user_creator/bin/gunicorn_start```
```bash
#!/bin/bash

NAME="gitlab_user_creator"                        # Name of the application
APPDIR=/webapps/gitlab_user_creator/app           # App directory
SOCKFILE=/webapps/gitlab_user_creator/run/gunicorn.sock  # we will communicte using this unix socket
USER=gitlab_user_creator                          # the user to run as
GROUP=webapps                                     # the group to run as
NUM_WORKERS=2                                     # how many worker processes should Gunicorn spawn

echo "Starting $NAME as `whoami`"

# Activate the virtual environment
cd $APPDIR
source ../venv/bin/activate

# Create the run directory if it doesn't exist
RUNDIR=$(dirname $SOCKFILE)
test -d $RUNDIR || mkdir -p $RUNDIR

# Start your App Unicorn
# Programs meant to be run under supervisor should not daemonize themselves (do not use --daemon)
exec ../venv/bin/gunicorn run:app \
  --name $NAME \
  --workers $NUM_WORKERS \
  --user=$USER --group=$GROUP \
  --bind=unix:$SOCKFILE \
  --log-level=debug \
  --log-file=-
```

Content of ```/etc/supervisor/conf.d/gitlab_user_creator.conf```

```
[program:gitlab_user_creator]
command = /webapps/gitlab_user_creator/bin/gunicorn_start             ; Command to start app
user = gitlab_user_creator                                            ; User to run as
stdout_logfile = /webapps/gitlab_user_creator/logs/gunicorn_supervisor.log   ; Where to write log messages
redirect_stderr = true                                                ; Save stderr in the same log
environment=LANG=en_US.UTF-8,LC_ALL=en_US.UTF-8                       ; Set UTF-8 as default encoding
```

## Setting Nginx

In ```/etc/gitlab/gitlab.rb``` you need to have the following parameters:
```
nginx['custom_gitlab_server_config'] = "location /myapps/external_user/static {\n alias /webapps/gitlab_user_creator/app/static;\n \n}\n location /myapps/external_user {\n proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n proxy_set_header Host $http_host;\n proxy_set_header X-Scheme $scheme;\n proxy_set_header X-Script-Name /myapps/external_user;\n proxy_redirect off;\n proxy_pass http://unix:/webapps/gitlab_user_creator/run/gunicorn.sock;\n \n}\n"
```

## Starting the system

First launch Gunicorn:
```bash
sudo supervisorctl update gitlab_user_creator # only needed the first time
sudo supervisorctl restart gitlab_user_creator
```

Second reconfigure GitLab:
```bash
sudo gitlab-ctl reconfigure
```
