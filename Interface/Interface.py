from flask import Flask,render_template,request, url_for, redirect, render_template,current_app, g,session,flash
import sqlite3
import click
import os 
from flask_sqlalchemy import SQLAlchemy
import pandas as pd 

from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

app = Flask(__name__)
db = SQLAlchemy()


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# create the extension
app.secret_key = "az900"
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
# initialize the app with the extension
db.init_app(app)



#Page index et connexion 
#---------------------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/Register', methods=['GET', 'POST'])
def Register():
    return render_template('Register.html')

@app.route('/SignIn', methods=['GET', 'POST'])
def SignIn():
    return render_template('SignIn.html')

@app.route('/SignInWrong', methods=['GET', 'POST'])
def SignInWrong():
    return render_template('SignInWrong.html')

@app.route('/logout')
def logout():
   session.pop('username', None)
   return redirect(url_for('index'))

@app.route('/verif', methods=['GET', 'POST'])
def verif():
    if request.method == "POST":
        try:
            user = db.session.execute(db.select(User).filter_by(email=request.form["Login"])).one()
            if(request.form["Mdp"]==user[0].mdp):
                session["login"]=request.form["Login"]
                return redirect(url_for('accueil'))
            else:
                return redirect(url_for('SignInWrong'))
        except : 
            return redirect(url_for('SignInWrong'))
    else:
        return redirect(url_for('SignInWrong'))
    
#---------------------------------------------------------------------------------------
#Database:
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    mdp = db.Column(db.String,nullable=False)
    nom = db.Column(db.String,nullable=False)
    prenom = db.Column(db.String,nullable=False)
    numTel = db.Column(db.String,nullable=False)
    DateEmbauche = db.Column(db.String,nullable=False)
    Contrat = db.Column(db.String,nullable=False)
    Poste = db.Column(db.String,nullable=False)
   

    def __repr__(self):
        return f'<User {self.email}>'
    
    
with app.app_context():
    db.create_all()
    
    
   
@app.route("/create", methods=["POST"])
def create_user():

    if request.method == "POST":
        
        user = User(
            email=request.form["Login"],
            mdp=request.form["Mdp"]
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('SignIn'))

    return redirect(url_for('SignIn'))

#---------------------------------------------------------------------------------------
#Page accueil

@app.route('/accueil')
def accueil():
    inf=get_info()
    return render_template('accueil.html',info=inf)

#---------------------------------------------------------------------------------------
#Page test global

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        
@app.route('/upload_file', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('test_global', name=filename))
    return

@app.route('/test_global')
def test_global():
    return render_template('test_global.html')
#---------------------------------------------------------------------------------------
#Page règles
@app.route('/regles')
def regles():
    return render_template('regles.html')
#---------------------------------------------------------------------------------------
#Page activitées : 
@app.route('/activitees')
def activitees():
    act=pd.read_csv("files/Activite.csv",sep=";")
    print(act)
    return render_template('activitees.html')


#---------------------------------------------------------------------------------------
#Fonction 
def get_info():
    info=[]
    user = db.session.execute(db.select(User).filter_by(email=session["login"])).one()
    info.append(user[0].email)
    info.append(user[0].nom)
    info.append(user[0].prenom)
    info.append(user[0].numTel)
    info.append(user[0].DateEmbauche)
    info.append(user[0].Contrat)
    info.append(user[0].Poste)
    
    return info

#---------------------------------------------------------------------------------------

#Lancement de l'application :
app.run(debug=False)



    