from flask import Flask, flash, redirect, render_template, \
     request, url_for, session, abort
from flask_oauthlib.client import OAuth, parse_response
from wtforms import Form, TextField, validators, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.csrf.session import SessionCSRF

import requests, json

app = Flask(__name__)
app.config.from_pyfile('settings.cfg')#, silent=True)

app.secret_key = 'some_secret'

oauth = OAuth()
remote_app = oauth.remote_app('remote_app',
    base_url=app.config['GITLAB_BASE']+'/api/v3/',
    request_token_url=None,
    access_token_url=app.config['GITLAB_BASE']+'/oauth/token',
    authorize_url=app.config['GITLAB_BASE']+'/oauth/authorize',
    app_key='GITLAB',
    access_token_method='POST'
)
oauth.init_app(app)


@remote_app.tokengetter
def get_gitlab_token():
    return session.get('gitlab_token')


@app.route('/account')
def account():
    logged_in = get_gitlab_token() is not None
    next_url = request.args.get('next') or request.referrer
    user = session['gitlab_user'] if 'gitlab_user' in session else None
    return render_template('account.html', logged_in=logged_in, next_url=next_url, user=user)

@app.route('/account/login')
def login():
    return remote_app.authorize(callback=url_for('oauth_authorized', _external=True,
        next=request.args.get('next') or request.referrer or None))

@app.route('/account/logout')
def logout():
    session.clear()
    flash(u'You logged out successfully.')
    return redirect(url_for('account'))

@app.route('/oauth-authorized')
def oauth_authorized():
    resp = remote_app.authorized_response()
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)
    
    r = remote_app.get('user', token=(resp['access_token'],''))
    if r.status != 200:
        flash(u'Request of /user information failed.', 'error')
        print r.text
        return redirect(next_url)
    
    user = r.data
    if user['external']:
        flash('The user %s is flagged as external.' % user['username'], 'error')
        return redirect(next_url)
    
    session['gitlab_token'] = (resp['access_token'], '')
    session['gitlab_user'] = user
    flash('You were signed in as %s' % user['username'])
    return redirect(next_url)


class RegistrationForm(Form):
    name = TextField('Name', [validators.Required()], render_kw={"placeholder": "Name"})
    username = TextField('Username', [validators.Required()], render_kw={"placeholder": "Username"})
    email = EmailField('Email Address', [validators.Required(), validators.Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Initial Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ], render_kw={"placeholder": "Password"})
    confirm = PasswordField('Repeat Password', render_kw={"placeholder": "Password"})
    
    class Meta:
        csrf = True
        csrf_secret = app.config['CSRF_SECRET']
    

@app.route('/', methods=['GET', 'POST'])
def index():
    token = get_gitlab_token()
    if token is None:
        return redirect(url_for('account', next=url_for('index')))
    
    
    form = RegistrationForm(request.form, meta={'csrf_context': session})
    if request.method == 'POST' and form.validate():
        data = {}
        data['name'] = form.name.data
        data['username'] = form.username.data
        data['email'] = form.email.data
        data['password'] = form.password.data
        data['projects_limit'] = 0
        data['external'] = True
        
        r = requests.post(app.config['GITLAB_BASE']+'/api/v3/users', data=json.dumps(data),
                          headers={'PRIVATE-TOKEN': app.config['GITLAB_ADMIN_TOKEN'], 'content-type': 'application/json'})
        if r.status_code == 201:
            flash('The user {} has been successfully created.'.format(form.username.data), 'success')
        else:
            flash('Problems when creating the user: {}'.format(r.json()['message']), 'error')
    
    return render_template('index.html', form=form, user=session['gitlab_user'])


if __name__ == "__main__":
    app.run()