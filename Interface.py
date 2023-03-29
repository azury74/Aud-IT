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
db.app=app
db.init_app(app)


#---------------------------------------------------------------------------------------
#AUTOMATISATION REFRESH CVE



def automation():
    
    with db.app.app_context():
    
        #db.session.add(Notif(description="Nouvelle faille CVjE : "+"...",etat="Nouveau"))
        #db.session.commit()
        
        
        reader=pd.read_csv("files/Histo_faille.csv")
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
     
           
            if(cve_ids[0]!=reader["CVE ID"].values[0]):
                db.session.add(Notif(description="Nouvelle faille CVE : "+cve_ids[0]+"...",etat="Nouveau"))
                db.session.commit()
                df.to_csv("files/Histo_faille.csv", index=False)
                '''
                import smtplib
                
                # Paramètres du serveur SMTP d'Orange
                smtp_server = 'smtp.orange.fr'
                smtp_port = 465
                username = 'louislaurent.74@orange.fr'
                password = 'Louis19'
                
                # Paramètres de l'e-mail
                from_addr = 'louislaurent.74@orange.fr'
                to_addr = 'destinataire@example.com'
                subject = 'Test d\'envoi d\'e-mail depuis Python'
                body = 'Ceci est un e-mail envoyé depuis Python.'
                
                # Création de l'e-mail
                message = f"From: {from_addr}\nTo: {to_addr}\nSubject: {subject}\n\n{body}"
                
                # Connexion au serveur SMTP et envoi de l'e-mail
                with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                    server.login(username, password)
                    server.sendmail(from_addr, to_addr, message)
                '''
            else :
                pass
        else:
            print("Erreur lors de la récupération des données.")

scheduler = BackgroundScheduler()
scheduler.api_enabled = True
scheduler.add_job(automation, IntervalTrigger(seconds=10))
scheduler.start()

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
    architecture=db.Column(db.String,nullable=False)
    
    def __repr__(self):
        return f'<User {self.email}>'
 
    
class Notif(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String, nullable=False)
    etat = db.Column(db.String, nullable=False)
    
   

    def __repr__(self):
        return f'<Notif {self.description,self.etat}>'
    
    

   
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




def choix_notif(arg):
    
    if(arg==None):
        no=None
    elif(arg=="afficher"):
        no="afficher"
        
        
    if(notif()):
        list_notif=get_list_notif()
    else :
        list_notif=["Pas de notification pour l'instant :)"]
        
        
    return list_notif,no
    
    
#---------------------------------------------------------------------------------------
#PAGE ACCEUIL
@app.route('/accueil',methods=["GET"])
def accueil():
    inf=get_info()
    
    result=choix_notif(request.args.get("notif"))
 
        
    
    return render_template('accueil.html',info=inf,notif=notif(),list_notif=result[0],no=result[1])

@app.route('/accueil_modif')
def accueil_modif():
    inf=get_info()
    
    result=choix_notif(request.args.get("notif"))
    
    return render_template('accueil_modif.html',info=inf,notif=notif(),list_notif=result[0],no=result[1])

@app.route('/env_modif',methods=['POST'])
def env_modif():
    user = db.session.execute(db.select(User).filter_by(email=session["login"])).one()
    config=request.form["sentence"]
    user[0].config=config
    db.session.commit()
    return redirect(url_for('accueil',info=get_info()) )


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
        
    result=choix_notif(request.args.get("notif"))
    return render_template('test_global.html',info=alerte,notif=notif(),list_notif=result[0],no=result[1],filedownload="installer/Aud'it.exe")
#---------------------------------------------------------------------------------------
#Page règles
@app.route('/regles')
def regles():
    regle=pd.read_csv("files/Règles.csv",sep=",",encoding='utf-8')
    resultx=[]
    result=choix_notif(request.args.get("notif"))
    typer=regle["Type_règle"].values
    for i in range(len(regle["Num"].values)):
        
        if(typer[i]=="Routage"):
            resultx.append({"Num":regle["Num"].values[i],"Description":regle["Description"].values[i],"Implémentation":regle["Implémentation"].values[i]})
    
    return render_template('regles.html',result=resultx,notif=notif(),list_notif=result[0],no=result[1])

@app.route('/regles_protec')
def regles_protec():
    regle=pd.read_csv("files/Règles.csv",sep=",",encoding='utf-8')
    resultx=[]
    result=choix_notif(request.args.get("notif"))
    typer=regle["Type_règle"].values
    for i in range(len(regle["Num"].values)):
        
        if(typer[i]=="Protection"):
            resultx.append({"Num":regle["Num"].values[i],"Description":regle["Description"].values[i],"Implémentation":regle["Implémentation"].values[i]})
    
    return render_template('regles_protec.html',result=resultx,notif=notif(),list_notif=result[0],no=result[1])


@app.route('/regles_protoc')
def regles_protoc():
    regle=pd.read_csv("files/Règles.csv",sep=",",encoding='utf-8')
    resultx=[]
    result=choix_notif(request.args.get("notif"))
    typer=regle["Type_règle"].values
    for i in range(len(regle["Num"].values)):
        
        if(typer[i]=="Protocole"):
            resultx.append({"Num":regle["Num"].values[i],"Description":regle["Description"].values[i],"Implémentation":regle["Implémentation"].values[i]})
    
    return render_template('regles_protoc.html',result=resultx,notif=notif(),list_notif=result[0],no=result[1])


@app.route('/regles_equip')
def regles_equip():
    regle=pd.read_csv("files/Règles.csv",sep=",",encoding='utf-8')
    resultx=[]
    result=choix_notif(request.args.get("notif"))
    typer=regle["Type_règle"].values
    for i in range(len(regle["Num"].values)):
        
        if(typer[i]=="Equipement"):
            resultx.append({"Num":regle["Num"].values[i],"Description":regle["Description"].values[i],"Implémentation":regle["Implémentation"].values[i]})
    
    return render_template('regles_equip.html',result=resultx,notif=notif(),list_notif=result[0],no=result[1])


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
    
    result=choix_notif(request.args.get("notif"))
    return render_template('activitees.html',result=resultot,notif=notif(),list_notif=result[0],no=result[1])
 
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
    
    list_notif = db.session.execute(db.select(Notif).filter_by(etat="Nouveau")).all()
 
    if(len(list_notif)!=0):
        for i in range(len(list_notif)):
            db.session.delete(list_notif[i][0])
            
            db.session.commit()
    
    result=choix_notif(request.args.get("notif"))
    return render_template('activitees_failles.html',result=resultot,notif=notif(),list_notif=result[0],no=result[1])

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

    result=choix_notif(request.args.get("notif"))    
    return render_template('activitees_anssi.html',result=resultot,notif=notif(),list_notif=result[0],no=result[1])


#---------------------------------------------------------------------------------------
#Page download
@app.route('/download', methods=['GET','POST'])
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
    result=choix_notif(request.args.get("notif"))
    return render_template('loader.html',notif=notif(),list_notif=result[0],no=result[1])

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
    time.sleep(2.5)

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
    
    score_protec=0
    tot_score_protec=0
    
    score_equ=0
    tot_score_equ=0
    
    nom_export=[]
    description_export=[]
    test_export=[]
    
    for i in range(len(nom)):
           
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
                        
                    elif(reg=="Protection"):
                        score_protec+=1
                        tot_score_protec+=1
                        test_export.append("Valide")
                        
                        
                    elif(reg=="Equipement"):
                        score_equ+=1
                        tot_score_equ+=1
                        test_export.append("Valide")
                else :
                    
                    if(reg == "Protocole"):
                        tot_score_prot+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Routage"):
                        tot_score_rout+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Protection"):
                        tot_score_protec+=1
                        test_export.append("Non Valide")
                        
                        
                    elif(reg=="Equipement"):
                        tot_score_equ+=1
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
                       
                   elif(reg=="Protection"):
               
                       score_protec+=1
                       tot_score_protec+=1
                       test_export.append("Valide")
                       
                       
                   elif(reg=="Equipement"):
                       score_equ+=1
                       tot_score_equ+=1
                       test_export.append("Valide")
                    
                else :
                    if(reg == "Protocole"):
                        tot_score_prot+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Routage"):
                        tot_score_rout+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Protection"):
               
                        tot_score_protec+=1
                        test_export.append("Non Valide")
                        
                        
                    elif(reg=="Equipement"):
                        tot_score_equ+=1
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
                        
                    elif(reg=="Protection"):
                        score_protec+=1
                        tot_score_protec+=1
                        test_export.append("Valide")
                        
                        
                    elif(reg=="Equipement"):
                        score_equ+=1
                        tot_score_equ+=1
                        test_export.append("Valide")
                    
                else :
            
                    if(reg == "Protocole"):
                        tot_score_prot+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Routage"):
                        tot_score_rout+=1
                        test_export.append("Non Valide")
                        
                    elif(reg=="Protection"):
                        tot_score_protec+=1
                        test_export.append("Non Valide")
                        
                        
                    elif(reg=="Equipement"):
                        tot_score_equ+=1
                        test_export.append("Non Valide")
                
                    
    pourcentage_test=int(((score_prot+score_rout+score_equ+score_protec)/(tot_score_prot+tot_score_rout+tot_score_equ+tot_score_protec))*100)

    
   
    
    datev1=datetime.datetime.now().strftime('%d_%m_%H_%M_%S')
    date=datetime.datetime.now().strftime('%d/%m/%Y %H:%M')
    nomFichier="historique/technique/audit_"+datev1+".csv"
    
    #Export historique :
    temp_res=[None]*len(nom_export)
    temp_res[0]="Score_audit="+str(pourcentage_test)+"/100"
    temp_res[1]="Date_audit="+date
    temp_res[2]="NbRèglesOkProt="+str(score_prot)+",NbRèglesNokProt="+str(tot_score_prot-score_prot)+",NbRèglesOkRout="+str(score_rout)+",NbRèglesNokRout="+str(tot_score_rout-score_rout)+",NbRègleOkEqu="+str(score_equ)+",NbRèglesNokEqu="+str(tot_score_equ-score_equ)+",NbRègleOkProtec="+str(score_protec)+",NbRèglesNokProtec="+str(tot_score_protec-score_protec)
   


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
    
    
    regles=[]
    regles.append([val[2].split(",")[0].split("=")[1],val[2].split(",")[1].split("=")[1]])
    regles.append([val[2].split(",")[2].split("=")[1],val[2].split(",")[3].split("=")[1]])
    regles.append([val[2].split(",")[4].split("=")[1],val[2].split(",")[5].split("=")[1]])
    regles.append([val[2].split(",")[6].split("=")[1],val[2].split(",")[7].split("=")[1]])
    

    
    nomFichier=filename
    
    result=choix_notif(request.args.get("notif"))
    return render_template('resultat.html',result=int(pourcentage_test),regles=regles,filename=nomFichier,notif=notif(),list_notif=result[0],no=result[1])



@app.route('/affichage_resultat_complet',methods=['GET'])
def affichage_resultat_complet():
    
    filename1=request.args.get("filename1")
    filename2=request.args.get("filename2")
    
    
    df1=pd.read_csv(filename1)
    df2=pd.read_csv(filename2)
    
    val=df1["Informations"].values
    val2=df2["Informations"].values
    pourcentage_test=val[0].split("=")[1].split("/")[0]
    
    
    regles=[]
    regles.append([val[2].split(",")[0].split("=")[1],val[2].split(",")[1].split("=")[1]])
    regles.append([val[2].split(",")[2].split("=")[1],val[2].split(",")[3].split("=")[1]])
    regles.append([val[2].split(",")[4].split("=")[1],val[2].split(",")[5].split("=")[1]])
    regles.append([val[2].split(",")[6].split("=")[1],val[2].split(",")[7].split("=")[1]])
    


    
    
    pourcentage_test_info=val2[0].split("=")[1].split("/")[0]
    
    result=choix_notif(request.args.get("notif"))
    return render_template('resultat_global.html',result=int(pourcentage_test),result2=int(pourcentage_test_info),regles=regles,filename=filename1,filename2=filename2,notif=notif(),list_notif=result[0],no=result[1])


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
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details.html',result=data,filename=filename,notif=notif(),list_notif=result[0],no=result[1])


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
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details.html',result=data,filename=filename,notif=notif(),list_notif=result[0],no=result[1])



@app.route('/details_equ',methods=['GET'])
def details_equ():
    filename=request.args.get("filename")
    df=pd.read_csv(filename)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Equipement"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details.html',result=data,filename=filename,notif=notif(),list_notif=result[0],no=result[1])



@app.route('/details_protec',methods=['GET'])
def details_protec():
    filename=request.args.get("filename")
    df=pd.read_csv(filename)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Protection"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details.html',result=data,filename=filename,notif=notif(),list_notif=result[0],no=result[1])




@app.route('/details_prot_complet',methods=['GET'])
def details_prot_complet():
    filename1=request.args.get("filename1")
    filename2=request.args.get("filename2")
    
    df=pd.read_csv(filename1)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Protocole"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details_complet.html',result=data,filename1=filename1,filename2=filename2,notif=notif(),list_notif=result[0],no=result[1])


@app.route('/details_rout_complet',methods=['GET'])
def details_rout_complet():
    filename1=request.args.get("filename1")
    filename2=request.args.get("filename2")
    df=pd.read_csv(filename1)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Routage"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details_complet.html',result=data,filename1=filename1,filename2=filename2,notif=notif(),list_notif=result[0],no=result[1])



@app.route('/details_equ_complet',methods=['GET'])
def details_equ_complet():
    
    filename1=request.args.get("filename1")
    filename2=request.args.get("filename2")
    df=pd.read_csv(filename1)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Equipement"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details_complet.html',result=data,filename1=filename1,filename2=filename2,notif=notif(),list_notif=result[0],no=result[1])



@app.route('/details_protec_complet',methods=['GET'])
def details_protec_complet():
    filename1=request.args.get("filename1")
    filename2=request.args.get("filename2")
    df=pd.read_csv(filename1)
    
    data=[]
    nom=df["Nom"].values
    des=df["Description"].values
    test=df["Test"].values
    type_regle=df["Type_règle"].values
    for i in range(len(df["Nom"].values)):
        if(type_regle[i]=="Protection"):
            data.append({"Nom":nom[i],"Type":type_regle[i],"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details_complet.html',result=data,filename1=filename1,filename2=filename2,notif=notif(),list_notif=result[0],no=result[1])


@app.route('/details_form',methods=['GET'])
def details_form():
    filename1=request.args.get("filename1")
    
    filename2=request.args.get("filename2")
    
    df=pd.read_csv(filename2)
    
    data=[]

    des=df["Description"].values
    test=df["Test"].values

    for i in range(len(df["Description"].values)):
        
        data.append({"Description":des[i],"Test":test[i]})
            
    result=choix_notif(request.args.get("notif"))
    return render_template('details_form.html',result=data,filename1=filename1,filename2=filename2,notif=notif(),list_notif=result[0],no=result[1])



@app.route('/retour',methods=['GET'])
def retour():
    filename=request.args.get("filename")
    
    return redirect(url_for("affichage_resultat", filename=filename))


@app.route('/retour_bis',methods=['GET'])
def retour_bis():
    filename1=request.args.get("filename1")
    filename2=request.args.get("filename2")
    
    return redirect(url_for("affichage_resultat_complet", filename1=filename1,filename2=filename2))


@app.route('/formulaire',methods=['GET','POST'])
def formulaire():
    filename=request.args.get("filename")
    return render_template("formulaire.html",filename=filename,notif=notif())


@app.route('/analyse_form',methods=['GET','POST'])
def analyse_form():
    
    filename=request.args.get("filename")
    
    
    df=pd.read_csv("files/Règles_formulaire.csv")
    description_export=df["Description"].values
    valeur=df["Valeur_attendue"].values
    
    score=0
    tot_score=0
    test_export=[]
    
    for i in range(len(description_export)):

        if(request.form[str(i)]==str(valeur[i])):

            score+=1
            tot_score+=1
            test_export.append("Valide")
        else :
            tot_score+=1
            test_export.append("Non Valide")
            
    pourcentage_test=int((score/tot_score)*100)
    
    datev1=datetime.datetime.now().strftime('%d_%m_%H_%M_%S')
    date=datetime.datetime.now().strftime('%d/%m/%Y %H:%M')
    nomFichier="historique/formulaire/audit_"+datev1+".csv"
    
    #Export historique :
    temp_res=[None]*len(description_export)
    temp_res[0]="Score_audit="+str(pourcentage_test)+"/100"
    temp_res[1]="Date_audit="+date   


    df_export=pd.DataFrame({"Informations":temp_res,"Description":description_export,"Test":test_export})
    
    df_export.to_csv(nomFichier,index=False,encoding="utf-8")
    
    
    return redirect(url_for("affichage_resultat_complet", filename1=filename,filename2=nomFichier))

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
    info.append(user[0].architecture)
    return info

def get_list_notif():
    info=[]
    notif = db.session.execute(db.select(Notif).filter_by(etat="Nouveau")).all()
                               
    for i in range(len(notif)):
        info.append(notif[i][0].description)
   
    
    return info

def notif():
   
    list_notif = db.session.execute(db.select(Notif).filter_by(etat="Nouveau")).all()
    if(len(list_notif) != 0):
        return True 
    
    else : 
        return False


def delete_file(path, filename):
    """
    Cette fonction permet de supprimer un fichier dans un dossier.
    """
    try:
        file_path = os.path.join(path, filename)
        os.unlink(file_path)
       
    except OSError:
        print("Une erreur s'est produite lors de la tentative de suppression du fichier.")


    
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        '''
        db.session.add(User(id=0,email="louis.laurent@esme.fr",mdp="esme2020",nom="Laurent",prenom="Louis",ets="ESME",offre="Premium",config="linux,servicedesk",architecture="PfSense"))
       
        db.session.commit()
        
        db.session.add(Notif(description="Nouvelle faille CVE : oui"+"...",etat="Nouveau"))
        db.session.commit()
        '''
        #---------------------------------------------------------------------------------------
        #LANCEMENT DES TACHES AUTO ET LANCEMENT DE L'APPLICATION
        try :
            app.run(debug=False)
        except : 
            scheduler.shutdown()


    