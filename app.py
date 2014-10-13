from __future__ import absolute_import, division, print_function, unicode_literals
from flask import Flask, Blueprint, render_template, redirect, url_for, request, session, jsonify
from flask_oauthlib.client import OAuth
from flask.ext.bootstrap import Bootstrap

main = Blueprint('main', __name__)
oauth = OAuth()
google = oauth.remote_app('google',
                          request_token_params={
                              'scope': 'https://www.googleapis.com/auth/userinfo.email'
                          },
                          base_url='https://www.googleapis.com/oauth2/v1/',
                          request_token_url=None,
                          access_token_method='POST',
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          app_key='GOOGLE')
bootstrap = Bootstrap()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_pyfile(config_name)

    bootstrap.init_app(app)
    oauth.init_app(app)

    if app.debug:
        from flask_debugtoolbar import DebugToolbarExtension
        DebugToolbarExtension(app)

    app.register_blueprint(main)

    return app


@main.route('/')
def index():
    if 'google_token' not in session:
        return redirect(url_for('.login'))

    me = google.get('userinfo')
    return jsonify({"data": me.data})


@main.route('/login')
def login():
    callback = url_for('.authorized', _external=True)
    return google.authorize(callback=callback)


@main.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('.index'))


@main.route('/authorized')
def authorized():
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    me = google.get('userinfo')
    return jsonify({"data": me.data})


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')
