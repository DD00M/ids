#!/usr/bin/env python3
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn import svm 

import numpy as np
from sklearn.preprocessing import LabelEncoder

import string
from sklearn.model_selection import GridSearchCV

from sklearn.feature_extraction.text import TfidfVectorizer

import nltk
from nltk.stem.porter import PorterStemmer

def get_importantFeatures(sent):
    sent = sent.lower()
    
    returnList = []
    sent = nltk.word_tokenize(sent)
    for i in sent:
        if i.isalnum():
            returnList.append(i)
    return returnList

def removing_stopWords(sent):
    returnList = []
    for i in sent:
        if i not in nltk.corpus.stopwords.words('english') and i not in string.punctuation:
            returnList.append(i)
    return returnList

def potter_stem(sent):
    returnList = []
    for i in sent:
        returnList.append(ps.stem(i))
    return " ".join(returnList)

ps = PorterStemmer()
def train_model(filename):
    df=pd.read_csv(filename)
    df.dropna(axis='columns',inplace=True)
    df.rename(columns={'v1':'label','v2':'email'},inplace=True)
    encoder = LabelEncoder()
    df['label'] = encoder.fit_transform(df['label'])
    df = df.drop_duplicates(keep='first')
    # nltk.download('punkt')
    # nltk.download('stopwords')

    df['imp_feature'] = df['email'].apply(get_importantFeatures)
    df['imp_feature'] = df['imp_feature'].apply(removing_stopWords)
    df['imp_feature'] = df['imp_feature'].apply(potter_stem)

    x = df['imp_feature']
    y = df["label"]
    x_train, x_test,y_train, y_test = train_test_split(x,y,test_size = 0.2,random_state=42)

    tfidf = TfidfVectorizer()
    feature = tfidf.fit_transform(x_train)

    tuned_parameters = {'kernel':['linear','rbf'],'gamma':[1e-3,1e-4], 'C':[1,10,100,1000]}

    model = GridSearchCV(svm.SVC(),tuned_parameters,verbose=True)
    model.fit(feature, y_train)

    y_predict = tfidf.transform(x_test)
    print("Accuracy:",model.score(y_predict,y_test))
    return model,tfidf


import pickle
def save_model_as_pickle(model):
    filename = 'finalized_model.sav'
    pickle.dump(model, open(filename, 'wb'))

def check_spam():
    global tfidf
    text = spam_text_Entry.get()
    is_spam = model.predict(tfidf.transform([text]))
    if is_spam == 1:
        print("text is spam")
        my_string_var.set("Result: text is spam")
    else:
        print("text is not spam")
        my_string_var.set("Result: text is not spam")
from tkinter import *
import tkinter as tk


model,tfidf=train_model('spam.csv')

# save_model_as_pickle(model)
# spam_model = pickle.load(open("finalized_model.sav",'rb'))


win = Tk()

win.geometry("400x600")
win.configure(background="cyan")
win.title("Sample Spam Detector")

title = Label(win, text="Spam Detector", bg="gray",width="300",height="2",fg="white",font=("Calibri 20 bold italic underline")).pack()

spam_text = Label(win, text="Enter your Text: ",bg="cyan", font=("Verdana 12")).place(x=12,y=100)
spam_text_Entry = Entry(win, textvariable=spam_text,width=33)
spam_text_Entry.place(x=300, y=110)

my_string_var = StringVar()
my_string_var.set("Result: ")

print_spam = Label(win, textvariable=my_string_var,bg="cyan", font=("Verdana 12")).place(x=12,y=200)

Button = Button(win, text="Submit",width="12",height="1",activebackground="red",bg="Pink",command=check_spam,font=("Verdana 12")).place(x=12,y=150)

win.mainloop()