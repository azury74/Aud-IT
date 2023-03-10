from flask import Flask,render_template,request, url_for, redirect, render_template,current_app, g,session,flash, send_from_directory
import sqlite3
import click
import os 
from flask_sqlalchemy import SQLAlchemy
import pandas as pd 
from datetime import datetime
from time import strftime
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
    ets = db.Column(db.String,nullable=False)
    offre = db.Column(db.String,nullable=False)
    
   

    def __repr__(self):
        return f'<User {self.email}>'
    
    
with app.app_context():
    db.create_all()
    db.session.add(User(id=0,email="louis.laurent@esme.fr",mdp="esme2020",nom="Laurent",prenom="Louis",ets="ESME",offre="Premium"))
    db.session.commit()
    
   
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
            return redirect(url_for('loader'))
    return

@app.route('/test_global')
def test_global():
    return render_template('test_global.html')
#---------------------------------------------------------------------------------------
#Page règles
@app.route('/regles')
def regles():
    regle=pd.read_csv("files/Règles.csv",sep=",",encoding='utf-8')
    result=[]
  
    for i in range(len(regle["Num"].values)):
        result.append({"Num":regle["Num"].values[i],"Description":regle["Description"].values[i],"Implémentation":regle["Implémentation"].values[i]})
    return render_template('regles.html',result=result)


#Page règles
@app.route('/regles_commu')
def regles_commu():
    regle=pd.read_csv("files/Règles_commu.csv",sep=",",encoding='utf-8')
    result=[]
   
    for i in range(len(regle["Num"].values)):
        result.append({"Num":regle["Num"].values[i],"Description":regle["Description"].values[i],"Implémentation":regle["Implémentation"].values[i]})
    return render_template('regles_commu.html',result=result)

#---------------------------------------------------------------------------------------
#Page activitées : 
@app.route('/activitees')
def activitees():
    histo_audit=pd.read_csv("files/Histo_audit.csv",sep=",",encoding='utf-8')
    histo_maj=pd.read_csv("files/Histo_maj.csv",sep=",",encoding='ISO-8859-1')
    histo_faille=pd.read_csv("files/Histo_faille.csv",sep=",",encoding='ISO-8859-1')

    result1=[]
    result2=[]
    result3=[]
    resultot=[]
    
    for i in range(len(histo_audit["Name"].values)):
        result1.append({"Nom":histo_audit["Name"].values[i],"Date":histo_audit["Date"].values[i],"ID":histo_audit["ID"].values[i],"Description":histo_audit["Description"].values[i],"Note":histo_audit["Note"].values[i],"lien":histo_audit["lienAUDIT"].values[i]})
    for i in range(len(histo_maj["Name"].values)):
        result3.append({"Nom":histo_maj["Name"].values[i],"Date":histo_maj["Date"].values[i],"ID":histo_maj["ID"].values[i],"Description":histo_maj["Description"].values[i],"lien":histo_maj["lien"].values[i]})
    for i in range(len(histo_faille["Name"].values)):
        result2.append({"Nom":histo_faille["Name"].values[i],"Date":histo_faille["Date"].values[i],"ID":histo_faille["ID"].values[i],"Description":histo_faille["Description"].values[i],"Note":histo_faille["Note"].values[i],"lien":histo_faille["lienfailleCSE"].values[i]})
        
        
    resultot.append(result1)
    resultot.append(result2)
    resultot.append(result3)
    return render_template('activitees.html',result=resultot)

#---------------------------------------------------------------------------------------
#Page download
@app.route('/download', methods=['GET'])
def download():
    
    return send_from_directory("files/AUDIT",request.args.get("filename"), as_attachment=True)
#---------------------------------------------------------------------------------------
#Page suppress
@app.route('/suppress', methods=['GET'])
def suppress():
    df=pd.read_csv("files/Histo_audit.csv",sep=",",encoding='utf-8')
    filename=request.args.get("filename")
    df = df.drop(df[df["lienAUDIT"]==filename].index)
    df.to_csv("files/Histo_audit.csv", index=False,encoding="utf-8")
    #os.remove("files/AUDIT/"+request.arg.get("filename"))
    return redirect(url_for('activitees'))

#---------------------------------------------------------------------------------------
#Page loader
@app.route('/loader')
def loader():
    return render_template('loader.html')

#---------------------------------------------------------------------------------------
#Page loader
@app.route('/result')
def result():
    histo_audit=pd.read_csv("files/Histo_audit.csv",sep=",",encoding='utf-8')
    date=datetime.now().strftime('%d/%m/%Y')
    nomFichier="audit_"+datetime.now().strftime('%d_%m')+".pdf"
    new_df=pd.DataFrame({'Name':["Analyse des fichiers"],"ID":[str(len(histo_audit["Name"].values)+1)],"Description":["Vous avez effectué un audit automatisé."],"Date":[date],"Note":["68/100"],"lienAUDIT":[nomFichier]})
    frames = [new_df,histo_audit]
    result = pd.concat(frames)
    result.to_csv("files/Histo_audit.csv", index=False,encoding="utf-8")
    return render_template('resultat.html')
#---------------------------------------------------------------------------------------
#Fonction 
def get_info():
    info=[]
    user = db.session.execute(db.select(User).filter_by(email=session["login"])).one()
    info.append(user[0].email)
    info.append(user[0].nom)
    info.append(user[0].prenom)
    info.append(user[0].ets)
    info.append(user[0].offre)
  
    
    return info

#---------------------------------------------------------------------------------------

#Lancement de l'application :
app.run(debug=False)



    