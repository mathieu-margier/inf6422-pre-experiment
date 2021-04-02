from flask import Flask
from routes import api

# Setup web server
app = Flask(__name__)

app.register_blueprint(api, url_prefix="/api")

@app.route('/')
def hello_world():
    return "Hello, world!"

if __name__ == "__main__":
    # Debug mode
    app.config['ENV'] = 'development'
    app.config['DEBUG'] = True
    app.config['TESTING'] = True

    app.run()
