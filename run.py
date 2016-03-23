from flask import Flask, flash, redirect, render_template, \
     request, url_for, session, abort
from flask_oauthlib.client import OAuth, parse_response
from wtforms import Form, BooleanField, TextField, PasswordField, validators

import requests

app = Flask(__name__)
app.config.from_pyfile('settings.cfg')#, silent=True)

app.secret_key = 'some_secret'

oauth = OAuth()
remote_app = oauth.remote_app('remote_app',
    base_url='https://git.comp.phys.ethz.ch/api/v3/',
    request_token_url=None,
    access_token_url='https://git.comp.phys.ethz.ch/oauth/token',
    authorize_url='https://git.comp.phys.ethz.ch/oauth/authorize',
    app_key='GITLAB',
    access_token_method='POST'
)
oauth.init_app(app)

# remote_app._client = flask_oauth.OAuthClient(remote_app._consumer, ca_certs='comp-phys-git.pem')

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

# @remote_app.authorized_handler
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
    email = TextField('Email Address', [validators.Required()], render_kw={"placeholder": "Email"})

@app.route('/', methods=['GET', 'POST'])
def index():
    token = get_gitlab_token()
    if token is None:
        return redirect(url_for('account', next=url_for('index')))
    
    
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        data = {}
        data['name'] = form.name
        data['username'] = form.username
        data['email'] = form.email
        data['project_limit'] = 0
        data['external'] = True
        r = requests.post('https://git.comp.phys.ethz.ch/api/v3/users', data=data, headers={'PRIVATE-TOKEN': app.config['GITLAB_ADMIN_KEY']})
        if r.status_code == 201:
            flash('The user {} has been successfully created.'.format(form.username), 'success')
        else:
            flash('Problems when creating the user: '+r.json()['message'], 'error')
    
    return render_template('index.html', form=form, user=session['gitlab_user'])

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     error = None
#     if request.method == 'POST':
#         if request.form['username'] != 'admin' or \
#                 request.form['password'] != 'secret':
#             error = 'Invalid credentials'
#         else:
#             flash('You were successfully logged in')
#             return redirect(url_for('index'))
#     return render_template('login.html', error=error)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')