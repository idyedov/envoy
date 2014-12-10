from __future__ import absolute_import, division, print_function, unicode_literals
from flask import Flask, Blueprint, Response, render_template, redirect, url_for, request, session, stream_with_context, jsonify
from flask_oauthlib.client import OAuth
from flask.ext.bootstrap import Bootstrap
import requests

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

def create_proxy_view(definition):
    def _subview(path=""):
        if 'google_token' not in session:
            return redirect(url_for('.login'))

        url = '{}{}{}{}'.format(
            definition['url'],
            '' if definition['url'].endswith('/') else '/',
            path,
            '?{}'.format(request.query_string) if request.query_string else ''
        )

        req = requests.get(url, stream=True)
        return Response(stream_with_context(req.iter_content()), content_type=req.headers['content-type'])

    return _subview


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_pyfile(config_name)

    bootstrap.init_app(app)
    oauth.init_app(app)

    if app.debug:
        from flask_debugtoolbar import DebugToolbarExtension
        DebugToolbarExtension(app)

    app.register_blueprint(main)

    default_app_set = False
    for app_definition in app.config['APPS']:
        view = create_proxy_view(app_definition)

        if app_definition['name'] == app.config['DEFAULT_APP']:
            app.add_url_rule('/', app_definition['name'], view)
            app.add_url_rule('/<path:path>', app_definition['name'], view)
            default_app_set = True
        else:
            app.add_url_rule('/{}/'.format(app_definition['name']), app_definition['name'], view)
            app.add_url_rule('/{}/<path:path>'.format(app_definition['name']), app_definition['name'], view)

    if not default_app_set:
        def _index_subview(path=""):
            if 'google_token' not in session:
                return redirect(url_for('.login'))

            me = google.get('userinfo')
            return jsonify({'data': me.data})

        app.add_url_rule('/', 'index', _index_subview)

    return app


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
    return jsonify({'data': me.data})


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')
