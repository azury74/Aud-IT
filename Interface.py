from flask import Flask,render_template,request, url_for, redirect, render_template,current_app, g,session,flash, send_from_directory
import sqlite3
import click
import os 
from flask_sqlalchemy import SQLAlchemy
import pandas as pd 
import datetime
from time import strftime
from werkzeug.utils import secure_filename
import spacy
from nltk.stem.snowball import SnowballStemmer
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from spacy.lang.fr.stop_words import STOP_WORDS as fr_stop

import  fr_core_news_sm
stemmer = SnowballStemmer(language='french')
nlp = fr_core_news_sm.load()

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt','csv'}

app = Flask(__name__)
db = SQLAlchemy()


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# create the extension
app.secret_key = "az900"
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
# initialize the app with the extension
db.init_app(app)




#PAGE INDEX ET PAGES DE CONNEXION 
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
#DATABASE LOCALE:
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    mdp = db.Column(db.String,nullable=False)
    nom = db.Column(db.String,nullable=False)
    prenom = db.Column(db.String,nullable=False)
    ets = db.Column(db.String,nullable=False)
    offre = db.Column(db.String,nullable=False)
    config=db.Column(db.String,nullable=False)
    
   

    def __repr__(self):
        return f'<User {self.email}>'
    
    
with app.app_context():
    db.create_all()
    #db.session.add(User(id=0,email="louis.laurent@esme.fr",mdp="esme2020",nom="Laurent",prenom="Louis",ets="ESME",offre="Premium",config="linux,servicedesk"))
    #db.session.commit()
    
   
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
#PAGE ACCEUIL
@app.route('/accueil')
def accueil():
    inf=get_info()
    return render_template('accueil.html',info=inf)

@app.route('/accueil_modif')
def accueil_modif():
    inf=get_info()
    return render_template('accueil_modif.html',info=inf)

@app.route('/env_modif',methods=['POST'])
def env_modif():
    user = db.session.execute(db.select(User).filter_by(email=session["login"])).one()
    config=request.form["sentence"]
    user[0].config=config
    db.session.commit()
    return redirect(url_for('accueil',info=get_info()) )

#---------------------------------------------------------------------------------------
#AUTOMATISATION REFRESH CVE
def automation():
    
    import requests

    # URL de l'API NVD pour récupérer les 100 dernières failles CVE
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=100&startIndex=0&sortBy=publishDate"
    # Envoie une requête GET à l'API pour récupérer les données
    response = requests.get(url)
    # Si la requête a réussi, crée un dataframe pandas contenant les informations CVSS des 100 dernières failles CVE
    if response.status_code == 200:
        data = response.json()
        cve_ids = []
        descriptions = []
        cvss_scores = []
        dates = []
        references = []
        for cve in data['result']['CVE_Items']:
            cve_id = cve['cve']['CVE_data_meta']['ID']
            description = cve['cve']['description']['description_data'][0]['value']
            cvss = cve['impact']['baseMetricV3']['cvssV3']['baseScore'] if 'baseMetricV3' in cve['impact'] else None
            date = cve['publishedDate']
            date = pd.to_datetime(date).strftime('%d-%m-%Y %H:%M') # Formate la date selon le format "jour-mois-année heure:minute"
            refs = [ref['url'] for ref in cve['cve']['references']['reference_data']] if 'references' in cve['cve'] else None
            cve_ids.append(cve_id)
            descriptions.append(description)
            cvss_scores.append(cvss)
            dates.append(date)
            references.append(refs[0])
        df = pd.DataFrame({'CVE ID': cve_ids, 'Description': descriptions, 'CVSS': cvss_scores, 'Date': dates, 'References': references})
        df.to_csv("files/Histo_faille.csv", index=False) # Exporte le dataframe dans un fichier CSV nommé "Histo_faille.csv"
        
    else:
        print("Erreur lors de la récupération des données.")
#---------------------------------------------------------------------------------------
#Page test global

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


#---------------------------------------------------------------------------------------
#FONCTION DROP FICHIER        
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
            filename = "audit_"+datetime.datetime.now().strftime('%d_%m_%H_%M')+".csv"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('loader'))
        
        else : 
            return redirect(url_for("test_global",alerte="Pas la bonne extension"))
    return

@app.route('/test_global', methods=['GET'])
def test_global():
    if request.args.get("alerte")=="Pas la bonne extension":
        alerte="Pas la bonne extension"
    else :
        alerte="none"
    return render_template('test_global.html',info=alerte)
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
#PAGES ACTIVITEES : 
@app.route('/activitees')
def activitees():
    histo_audit=pd.read_csv("files/Histo_audit.csv",sep=",",encoding='utf-8')
    
   
    result1=[]
    
    resultot=[]
    
    for i in range(len(histo_audit["Name"].values)):
        result1.append({"Nom":histo_audit["Name"].values[i],"Date":histo_audit["Date"].values[i],"ID":histo_audit["ID"].values[i],"Description":histo_audit["Description"].values[i],"Note":histo_audit["Note"].values[i],"lien":histo_audit["lienAUDIT"].values[i]})
    
        
    resultot.append(result1)
    resultot.append([])
    resultot.append([])
    return render_template('activitees.html',result=resultot)
 
@app.route('/activitees_faille')
def activitees_faille():
    
    df=pd.read_csv("files/Histo_faille.csv",sep=",",encoding='ISO-8859-1')

    
    result2=[]
    resultot=[]
    
    for i in range(len(df["CVE ID"].values)):
        result2.append({"Nom":df["CVE ID"].values[i],"CVSS":df["CVSS"].values[i],"Date":df["Date"].values[i],"Description":df["Description"].values[i][0:100]+" ...","lien":df["References"].values[i]})

        
    resultot.append([])
    resultot.append(result2[0:10])
    resultot.append([])
    return render_template('activitees_failles.html',result=resultot)

#Page activitées : 
@app.route('/activitees_anssi')
def activitees_anssi():
   
    histo_maj=pd.read_csv("files/Histo_maj.csv",sep=",",encoding='ISO-8859-1')
     
    result3=[]
    resultot=[]
    
    for i in range(len(histo_maj["Name"].values)):
        result3.append({"Nom":histo_maj["Name"].values[i],"Date":histo_maj["Date"].values[i],"ID":histo_maj["ID"].values[i],"Description":histo_maj["Description"].values[i],"lien":histo_maj["lien"].values[i]})

        
    resultot.append([])
    resultot.append([])
    resultot.append(result3)
    return render_template('activitees_anssi.html',result=resultot)


#---------------------------------------------------------------------------------------
#Page download
@app.route('/download', methods=['GET'])
def download():
    return send_from_directory("",request.args.get("filename"), as_attachment=True)
#---------------------------------------------------------------------------------------
#Page suppress
@app.route('/suppress', methods=['GET'])
def suppress():
    df=pd.read_csv("files/Histo_audit.csv",sep=",",encoding='utf-8')
    filename=request.args.get("filename")
    df = df.drop(df[df["lienAUDIT"]==filename].index)
    df.to_csv("files/Histo_audit.csv", index=False,encoding="utf-8")
    os.remove(request.args.get("filename"))
    return redirect(url_for('activitees'))

#---------------------------------------------------------------------------------------
#Page loader
@app.route('/loader')
def loader():
    render_template('loader.html')
    return render_template('loader.html')

#---------------------------------------------------------------------------------------
#REFRESH DES CVES 
@app.route('/refresh_cve')
def refresh_cve():
    
    
    import requests
    import json 
    
    
    aujourdhui = datetime.datetime.today().strftime('%Y-%m-%dT00:00:00.000')

    # Calcul de la date d'il y a deux jours
    deux_jours = datetime.datetime.today() - datetime.timedelta(days=3)
    deux_jours = deux_jours.strftime('%Y-%m-%dT00:00:00.000')

    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200&pubStartDate="+deux_jours+"&pubEndDate="+aujourdhui
    
    cve_ids = []
    descriptions = []
    cvss_scores = []
    dates = []
    references = []
    # Envoi de la requête à l'API
    response = requests.get(api_url)

    # Analyse de la réponse JSON de l'API
    data = json.loads(response.text)

    # Parcours des 100 dernières failles CVE
    for cve_item in data["vulnerabilities"]:
        cve_id = cve_item['cve']['id']
        description = cve_item['cve']['descriptions'][0]['value']
        try :
            cvss_score = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
            
        except :
            cvss_score ="None"
            
        date = cve_item['cve']['published']
        
        try :
        
            reference = cve_item['cve']['references'][0]['url']
        except :
            reference="None"
        
        cve_ids.append(cve_id)
        descriptions.append(description)
        cvss_scores.append(cvss_score)
        dates.append(pd.to_datetime(date).strftime('%d-%m-%Y %H:%M'))
        references.append(reference)
        
    
    df = pd.DataFrame({'CVE ID': cve_ids, 'Description': descriptions, 'CVSS': cvss_scores, 'Date': dates, 'References': references})
        


    info=get_info()
    cve_idsv2=[]
    descriptionsv2=[]
    cvss_scoresv2=[]
    datesv2=[]
    referencesv2=[]
    
    
    list_config=info[5].split(",")
    import re 
    string_check= re.compile('[@_!#$%^&*()<\\>?/\|}{~:=";.]') 
    for i in range(len(df["CVE ID"].values)):
        doc = nlp(df["Description"].values[i])
       
        #--------------------------------------------------------------------
        #ON SPLIT LA PHRASE EN MOTS CLES :
        phrase=[]
        for word in doc:
            if(not(any(chr.isdigit() for chr in word.text))):
                if(not word.like_num):
                    if(not word.is_punct):
                        if(not(word.is_space)):
                            if(not(word.like_url)):
                                if (not(word.is_stop)):
                                    if (not(word.like_email)):
                                        if(len(word.text)>2 and len(word.text)<15):
                                            if(string_check.search(word.text) == None):
                                                phrase.append(stemmer.stem(word.text))
                                         
        for p in list_config:
            if(p in phrase):
                cve_idsv2.append(df["CVE ID"].values[i])
                descriptionsv2.append(df["Description"].values[i])
                cvss_scoresv2.append(df["CVSS"].values[i])
                datesv2.append(df["Date"].values[i])
                referencesv2.append(df["References"].values[i])
                
        
    
    df_res= pd.DataFrame({'CVE ID': cve_idsv2, 'Description': descriptionsv2, 'CVSS': cvss_scoresv2, 'Date': datesv2, 'References': referencesv2})
    df_res=df_res.iloc[::-1]
    df_res.to_csv("files/Histo_faille.csv", index=False) # Exporte le dataframe dans un fichier CSV nommé "Histo_faille.csv"
   

    
            
    return redirect(url_for('activitees_faille'))


#---------------------------------------------------------------------------------------
#PAGE DE CALCULS DES RESULTATS
@app.route('/result',methods=['GET'])
def result():

    #Lecture du fichier extrait 
    import os
    import time 
    time.sleep(2)

    # Chemin du dossier contenant les fichiers
    chemin_dossier = 'uploads'
    liste_fichiers = os.listdir(chemin_dossier)
    
    #Lecture du fichier 
    df=pd.read_csv(chemin_dossier+"/"+liste_fichiers[0])
    regle=pd.read_csv("files/Règles.csv")
    
    #Vérification des règles 
    
    nom=df["Nom"].values
    values=df["Valeur_attendue"].values
    
    
    nom_regle=regle["Nom"].values
    description=regle["Description"].values
    valeur_attendues=regle["Valeur_attendue"].values
    type_test=regle["Type_test"].values
    type_regle=regle["Type_règle"].values
    
    
    score_prot=0
    tot_score_prot=0
    
    score_rout=0
    tot_score_rout=0
    
    nom_export=[]
    description_export=[]
    test_export=[]
    
    for i in range(len(nom)):
        if(nom[i] in nom_regle):
            x=list(nom_regle).index(nom[i])
            val=valeur_attendues[x]
            des=description[x]
            reg=type_regle[x]
            
            nom_export.append(nom[i])
            description_export.append(des)
            
            if(type_test[i] == "int"):
                
                if(int(val) == int(values[i]) or int(val) >= int(values[i])):
                    
                    if(reg == "Protocole"):
                        score_prot+=1
                        tot_score_prot+=1
                        test_export.append("Valide")
                        
                    elif(reg=="Routage"):
                        score_rout+=1
                        tot_score_rout+=1
                        test_export.append("Valide")
                else :
                    
                    if(reg == "Protocole"):
                        tot_score_prot+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Routage"):
                        tot_score_rout+=1
                        test_export.append("Non Valide")
                    
            elif(type_test[i] == "bool"):
                if(val == values[i]):
                   if(reg == "Protocole"):
                       score_prot+=1
                       tot_score_prot+=1
                       test_export.append("Valide")
                       
                   elif(reg=="Routage"):
                       score_rout+=1
                       tot_score_rout+=1
                       test_export.append("Valide")
                    
                else :
                    if(reg == "Protocole"):
                        tot_score_prot+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Routage"):
                        tot_score_rout+=1
                        test_export.append("Non Valide")
                    
            elif(type_test[i] == "float"):
       
                if(float(val) == float(values[i]) or float(val) < float(values[i])):
                    if(reg == "Protocole"):
                        score_prot+=1
                        tot_score_prot+=1
                        test_export.append("Valide")
                        
                    elif(reg=="Routage"):
                        score_rout+=1
                        tot_score_rout+=1
                        test_export.append("Valide")
                    
                else :
            
                    if(reg == "Protocole"):
                        tot_score_prot+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Routage"):
                        tot_score_rout+=1
                        test_export.append("Non Valide")
                
                    
    pourcentage_test=int(((score_prot+score_rout)/(tot_score_prot+tot_score_rout))*100)

    
   
    
    datev1=datetime.datetime.now().strftime('%d_%m_%H_%M_%S')
    date=datetime.datetime.now().strftime('%d/%m/%Y %H:%M')
    nomFichier="historique/audit_"+datev1+".csv"
    
    #Export historique :
    temp_res=[None]*len(nom_export)
    temp_res[0]="Score_audit="+str(pourcentage_test)+"/100"
    temp_res[1]="Date_audit="+date
    temp_res[2]="NbRèglesOkProt="+str(score_prot)+",NbRèglesNokProt="+str(tot_score_prot-score_prot)+",NbRèglesOkRout="+str(score_rout)+",NbRèglesNokRout="+str(tot_score_rout-score_rout)
   
    df_export=pd.DataFrame({"Informations":temp_res,"Nom":nom_export,"Description":description_export,"Test":test_export,"Type_règle":type_regle})
    df_export.to_csv(nomFichier,index=False,encoding="utf-8")
    
    #Ajout dans le fichier d'historique 
    histo_audit=pd.read_csv("files/Histo_audit.csv",sep=",",encoding='utf-8')
   
    
    new_df=pd.DataFrame({'Name':["Analyse des fichiers"],"ID":[str(len(histo_audit["Name"].values)+1)],"Description":["Vous avez effectué un audit automatisé."],"Date":[date],"Note":[str(pourcentage_test)+"/100"],"lienAUDIT":[nomFichier]})
    frames = [new_df,histo_audit]
    result = pd.concat(frames)
    result.to_csv("files/Histo_audit.csv", index=False,encoding="utf-8")
    
    delete_file("uploads", liste_fichiers[0])
    
    return redirect(url_for("affichage_resultat", filename=nomFichier))

#---------------------------------------------------------------------------------------
#PAGE D'AFFICHAGE DES RESULTATS : 
@app.route('/affichage_resultat',methods=['GET'])
def affichage_resultat():
    filename=request.args.get("filename")
    df=pd.read_csv(filename)
    val=df["Informations"].values
    pourcentage_test=val[0].split("=")[1].split("/")[0]
    
    nbRegleGOkProt=val[2].split(",")[0].split("=")[1]
    nbRegleGNokProt=val[2].split(",")[1].split("=")[1]
    
    nbRegleGOkRout=val[2].split(",")[2].split("=")[1]
    nbRegleGNokRout=val[2].split(",")[3].split("=")[1]
    
    nomFichier=filename
    return render_template('resultat.html',result=int(pourcentage_test),nbRegleGOkProt=nbRegleGOkProt,nbRegleGNokProt=nbRegleGNokProt,nbRegleGOkRout=nbRegleGOkRout,nbRegleGNokRout=nbRegleGNokRout,filename=nomFichier)



@app.route('/details_prot',methods=['GET'])
def details_prot():
    filename=request.args.get("filename")
    df=pd.read_csv(filename)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Protocole"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
    return render_template('details.html',result=data,filename=filename)


@app.route('/details_rout',methods=['GET'])
def details_rout():
    filename=request.args.get("filename")
    df=pd.read_csv(filename)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Routage"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
    return render_template('details.html',result=data,filename=filename)


@app.route('/retour',methods=['GET'])
def retour():
    filename=request.args.get("filename")
    
    return redirect(url_for("affichage_resultat", filename=filename))

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
    info.append(user[0].config)
  
    
    return info

def delete_file(path, filename):
    """
    Cette fonction permet de supprimer un fichier dans un dossier.
    """
    try:
        file_path = os.path.join(path, filename)
        os.unlink(file_path)
       
    except OSError:
        print("Une erreur s'est produite lors de la tentative de suppression du fichier.")



#---------------------------------------------------------------------------------------
#LANCEMENT DES TACHES AUTO ET LANCEMENT DE L'APPLICATION
scheduler = BackgroundScheduler()
scheduler.add_job(automation, IntervalTrigger(hours=2))
scheduler.start()
#Lancement de l'application :
app.run(debug=False)



    