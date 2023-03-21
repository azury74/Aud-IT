# Automated audit tool for information systems security

## Authors : 
  - COHEN Lisa
  - BEN BELLA Walid
  - LAURENT Louis


## Description :

This program combines network architecture and configuration analysis scripts with a FLASK web platform for easy and efficient use of the algorithm. The algorithm checks more than 300 official rules of the ANSSI to allow you to secure your information systems.

 Algorithm area :

  - Firewalls settings
  - Routing rules
  - Administration of rights

We also implement a live notification system of CVE. The system analyse each description of CVE to display only the one that matters to the customer.

## Installation :

In order to use the interface, you will need to install Flask : 

Install Flask, with pip :

```node
$ pip install Flask
```

Install Pandas, with pip : 
```node
$ pip install pandas
```

### Start the project :

In order to start the project, just launch "Interface.py" in the Interface folder. 

Then open the following page in your web browser : 

<http://127.0.0.1:5000/>


## Libraries :

Flask :

<https://flask.palletsprojects.com/en/2.1.x/installation/>

Surprise :

<https://surprise.readthedocs.io/en/stable/>

Panda :

<https://pandas.pydata.org/docs/>
