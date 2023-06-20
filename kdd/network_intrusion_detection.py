import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from sklearn import preprocessing
from sklearn.feature_selection import RFE
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split # Import train_test_split function
import warnings
warnings.filterwarnings("ignore")

#toate trasaturile sunt transformate in valori numerice folosind one  hot encoding. Totodata, valodile sunt scalate astfel incat sa nu existe valori mult prea mari care sa aiba o pondere foarte mare in evaluarea rezultatelor    
# train_df=pd.read_csv('KDDTrain+.txt',sep=',',encoding='utf-8')


col_names =['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
            'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
            'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
            'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
            'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
            'dst_host_srv_rerror_rate','attack','level']

train_df=pd.read_csv('KDDTrain+.txt',sep=',',encoding='utf-8',header=None, names=col_names)
test_df=pd.read_csv('KDDTest+.txt',sep=',',encoding='utf-8',header=None,names=col_names)
# print(train_df.head())
# print('Label distribution Training set:')
# print(train_df['label'].value_counts())

# print(train_df.isnull().sum(),test_df.isnull().sum())



#feature selection
#eliminam datele redundante si irelevante selectand un subset din acestea care ajuta sa descrie problema noastra
#Cu anova F-test se analizeaza fiecare trasatura individual pentru a se determina legatura dintre trasatura in sine si categories (cat de relevanta e trasatura repsectiva pentru incadrarea intrrii in categoria cu care este etichetata)
#dupa care, folosind metoda SecondPercentile vom selecta trasaturile care au cele mai mari valori (adica descriu setul de date cel mai bine, au cea mai mare relevanta)
#identificam trasaturile care reprezinta categorii
print('Training set:')
[print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=len(train_df[col_name].unique())))for col_name in train_df.columns if train_df[col_name].dtypes == 'object']
print(train_df['protocol_type'].unique())
print('Distribution of categories in service:')
print(train_df['service'].value_counts().sort_values(ascending=False).head())
print('Distribution of categories in flag:')
print(train_df['flag'].value_counts().sort_values(ascending=False).head())
#pentru a folosi OneHotEncoder pentru a transforma trasaturile cu numar finit de valori, acestea trebuie sa fie valori intregi
#rezultatul aplicarii algoritmului va fi o matrice unde fiecare coloana corespunde unei valori asociata trasaturii  [0,n_values)
#pentru a trasforma trasaturile categorice in valori numerice vom folosi LabelEncoder

categorical_features=['protocol_type','service','flag']
train_df_categorical_values = train_df[categorical_features]
test_df_categorical_values = test_df[categorical_features]


unique_protocol=['Protocol_type_' + x for x in sorted(train_df.protocol_type.unique())]
unique_service=['Service_' + x for x in sorted(train_df.service.unique())]
unique_flag=['Flag_' + x for x in sorted(train_df.flag.unique())]
dummy_columns_train=unique_protocol+unique_flag+unique_service
#pentru setul de date de test protocol si flag au aceleasi valori, difera doar pentru service
dummy_columns_test=unique_protocol+unique_flag+['Service_' + x for x in sorted(test_df.service.unique())]


label_encoder=LabelEncoder()
train_df_categorical_values_enc=train_df_categorical_values.apply(label_encoder.fit_transform)
test_df_categorical_values_enc=test_df_categorical_values.apply(label_encoder.fit_transform)

one_hot_encoding=OneHotEncoder()
train_df_categorical_values_enc=one_hot_encoding.fit_transform(train_df_categorical_values_enc)
test_df_categorical_values_enc=one_hot_encoding.fit_transform(test_df_categorical_values_enc)

train_df_final=pd.DataFrame(train_df_categorical_values_enc.toarray(),columns=dummy_columns_train)
test_df_final=pd.DataFrame(test_df_categorical_values_enc.toarray(),columns=dummy_columns_test)

#trebuie echilibrate seturile de date, asa ca adaugam 6 categorii din setul de antrenare in setul de testare
difference=['Service_' + x for x in list(set(train_df['service'].tolist()) - set(test_df['service'].tolist()))]
print(difference)
for col in difference:
    test_df_final[col]=0
#punem rezultatele encodate inapoi in setul initial, in locul trasaturilor categorice initiale
train_df=train_df.join(train_df_final)
train_df.drop(['flag','service','protocol_type'],axis=1,inplace=True)
test_df=test_df.join(test_df_final)
test_df.drop(['flag','service','protocol_type'],axis=1,inplace=True)


#0=normal
#1=Dos
#2=Probe
#3=R2L
#4=U2R
train_df['attack']=train_df['attack'].replace({ 'normal' : 0, 
                            'neptune' : 1 ,'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                           'ipsweep' : 2,'nmap' : 2,'portsweep' : 2,'satan' : 2,'mscan' : 2,'saint' : 2
                           ,'ftp_write': 3,'guess_passwd': 3,'imap': 3,'multihop': 3,'phf': 3,'spy': 3,'warezclient': 3,'warezmaster': 3,'sendmail': 3,'named': 3,'snmpgetattack': 3,'snmpguess': 3,'xlock': 3,'xsnoop': 3,'httptunnel': 3,
                           'buffer_overflow': 4,'loadmodule': 4,'perl': 4,'rootkit': 4,'ps': 4,'sqlattack': 4,'xterm': 4})

test_df['attack']=test_df['attack'].replace({ 'normal' : 0, 
                            'neptune' : 1 ,'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                           'ipsweep' : 2,'nmap' : 2,'portsweep' : 2,'satan' : 2,'mscan' : 2,'saint' : 2
                           ,'ftp_write': 3,'guess_passwd': 3,'imap': 3,'multihop': 3,'phf': 3,'spy': 3,'warezclient': 3,'warezmaster': 3,'sendmail': 3,'named': 3,'snmpgetattack': 3,'snmpguess': 3,'xlock': 3,'xsnoop': 3,'httptunnel': 3,
                           'buffer_overflow': 4,'loadmodule': 4,'perl': 4,'rootkit': 4,'ps': 4,'sqlattack': 4,'xterm': 4})





#impartim dataframeul pe datarframeuri separate specifice fiecarul tip de atac
dos_df=train_df[~train_df['attack'].isin([2,3,4])]
probe_df=train_df[~train_df['attack'].isin([1,3,4])]
r2l_df=train_df[~train_df['attack'].isin([1,2,4])]
u2r_df=train_df[~train_df['attack'].isin([1,2,3])]

dos_df_test=test_df[~test_df['attack'].isin([2,3,4])]
probe_df_test=test_df[~test_df['attack'].isin([1,3,4])]
r2l_df_test=test_df[~test_df['attack'].isin([1,2,4])]
u2r_df_test=test_df[~test_df['attack'].isin([1,2,3])]

#separam etichetele de seturile de date (x si y)

X_dos_train=dos_df.drop('attack',axis=1)
Y_dos_train=dos_df['attack']
X_dos_test=dos_df_test.drop('attack',axis=1)
Y_dos_test=dos_df_test['attack']

X_probe_train=probe_df.drop('attack',axis=1)
Y_probe_train=probe_df['attack']
X_probe_test=probe_df_test.drop('attack',axis=1)
Y_probe_test=probe_df_test['attack']

X_r2l_train=r2l_df.drop('attack',axis=1)
Y_r2l_train=r2l_df['attack']
X_r2l_test=r2l_df_test.drop('attack',axis=1)
Y_r2l_test=r2l_df_test['attack']

X_u2r_train=u2r_df.drop('attack',axis=1)
Y_u2r_train=u2r_df['attack']
X_u2r_test=u2r_df_test.drop('attack',axis=1)
Y_u2r_test=u2r_df_test['attack']

col_names_dos_train=X_dos_train.columns
col_names_dos_test=X_dos_test.columns
col_names_probe_train=X_probe_train.columns
col_names_probe_test=X_probe_test.columns
col_names_r2l_train=X_r2l_train.columns
col_names_r2l_test=X_r2l_test.columns
col_names_u2r_train=X_u2r_train.columns
col_names_u2r_test=X_u2r_test.columns


#StandardScaler e folosit sa redimensioneze valorile campurilor astfel incat media sa fie 0 si deviatia standard 1 (ajuta la calculul mai usor al probabilitatii de aparitie a anumitor valori si pentru a compar)

X_dos_train=preprocessing.StandardScaler().fit(X_dos_train).transform(X_dos_train)
X_probe_train=preprocessing.StandardScaler().fit(X_probe_train).transform(X_probe_train)
X_r2l_train=preprocessing.StandardScaler().fit(X_r2l_train).transform(X_r2l_train)
X_u2r_train=preprocessing.StandardScaler().fit(X_u2r_train).transform(X_u2r_train)

X_dos_test=preprocessing.StandardScaler().fit(X_dos_test).transform(X_dos_test)
X_probe_test=preprocessing.StandardScaler().fit(X_probe_test).transform(X_probe_test)
X_r2l_test=preprocessing.StandardScaler().fit(X_r2l_test).transform(X_r2l_test)
X_u2r_test=preprocessing.StandardScaler().fit(X_u2r_test).transform(X_u2r_test)
#modelul va fi evaluat folosind mai multe metrici specifice: acuratetea, matricea de confuzie, scorul F1
#feature selection - selectamm cele mai relevante trasaturi care influenteaza incadrarea unei intrari a setului nostru de date intr-o anumita categorie
from sklearn.feature_selection import SelectPercentile, f_classif
np.seterr(divide='ignore', invalid='ignore')
selector=SelectPercentile(f_classif, percentile=10)

#momentan. X_dos_train_new este un np.ndarray, nu un dataframe, obtinem coloanele selectate
X_dos_new = selector.fit_transform(X_dos_train,Y_dos_train)
new_col_index_dos=[i for i, x in enumerate(selector.get_support()) if x]
new_col_name_dos=list( col_names_dos_train[i] for i in new_col_index_dos )
print("feature selection for Dos: ",new_col_name_dos)

X_probe_new=selector.fit_transform(X_probe_train,Y_probe_train)
new_col_index_probe=[i for i, x in enumerate(selector.get_support()) if x]
new_col_name_probe=list( col_names_probe_train[i] for i in new_col_index_probe )
print("feature selection for probe: ",new_col_name_probe)

X_r2l_new=selector.fit_transform(X_r2l_train,Y_r2l_train)
new_col_index_r2l=[i for i, x in enumerate(selector.get_support()) if x]
new_col_name_r2l=list( col_names_r2l_train[i] for i in new_col_index_r2l )
print("feature selection for r2l: ",new_col_name_r2l)

X_u2r_new=selector.fit_transform(X_u2r_train,Y_u2r_train)
new_col_index_u2r=[i for i, x in enumerate(selector.get_support()) if x]
new_col_name_u2r=list( col_names_u2r_train[i] for i in new_col_index_u2r )
print("feature selection for u2r: ",new_col_name_u2r)


from sklearn.feature_selection import RFE
from sklearn.tree import DecisionTreeClassifier
# Create a decision tree classifier. By convention, clf means 'classifier'
clf = DecisionTreeClassifier(random_state=0)

#rank all features, i.e continue the elimination until the last one
rfe = RFE(clf, n_features_to_select=1)

rfe.fit(X_dos_new, Y_dos_train.astype('int'))
print ("DoS Features sorted by their rank:")
print (sorted(zip(map(lambda x: round(x, 4), rfe.ranking_), new_col_name_dos)))
rfe.fit(X_probe_new, Y_probe_train.astype('int'))
print ("Probe Features sorted by their rank:")
print (sorted(zip(map(lambda x: round(x, 4), rfe.ranking_), new_col_name_probe)))
rfe.fit(X_r2l_train, Y_r2l_train.astype('int'))
print ("R2L Features sorted by their rank:")
print (sorted(zip(map(lambda x: round(x, 4), rfe.ranking_), new_col_name_r2l)))
rfe.fit(X_u2r_new, Y_u2r_train.astype('int'))
print ("U2r Features sorted by their rank:")
print (sorted(zip(map(lambda x: round(x, 4), rfe.ranking_), new_col_name_u2r)))


x_train_list=[X_dos_train,X_probe_train,X_r2l_train,X_u2r_train]
y_train_list=[Y_dos_train,Y_probe_train,Y_r2l_train,Y_u2r_train]
x_test_list=[X_dos_test,X_probe_test,X_r2l_test,X_u2r_test]
y_test_list=[Y_dos_test,Y_probe_test,Y_r2l_test,Y_u2r_test]


##############################DECISION TREE#############################
from sklearn.model_selection import cross_val_score
from sklearn import metrics
from mlxtend.plotting import plot_confusion_matrix
def apply_decision_tree(x_train_list,y_train_list,x_test_list,y_test_list):
    for i in range(4):
        clf =    DecisionTreeClassifier(random_state=0)
        clf.fit(x_train_list[i],y_train_list[i].astype(int))
        Confusion_Matrix = metrics.confusion_matrix(y_test_list[i], clf.predict(x_test_list[i]))
        plot_confusion_matrix(Confusion_Matrix,class_names=['Normal', 'Attack'],figsize=(5.55,5), colorbar= "blue")
        plt.show()
        accuracy = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='accuracy')
        print("Accuracy: %0.5f (+/- %0.5f)" % (accuracy.mean(), accuracy.std() * 2))
        precision = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='precision')
        print("Precision: %0.5f (+/- %0.5f)" % (precision.mean(), precision.std() * 2))
        recall = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='recall')
        print("Recall: %0.5f (+/- %0.5f)" % (recall.mean(), recall.std() * 2))
        f = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='f1')
        print("F-measure: %0.5f (+/- %0.5f)" % (f.mean(), f.std() * 2))


# apply_decision_tree(x_train_list,y_train_list,x_test_list,y_test_list)

##############RANDOM FOREST##################################
from sklearn.ensemble import RandomForestClassifier

def apply_random_forest(x_train_list,y_train_list,x_test_list,y_test_list):
    for i in range(4):
        clf=RandomForestClassifier(random_state=0)
        clf.fit(x_train_list[i], y_train_list[i].astype(int))
        Confusion_Matrix=metrics.confusion_matrix(y_test_list[i],clf.predict(x_test_list[i]))
        plot_confusion_matrix(Confusion_Matrix,class_names=['Normal', 'Attack'],figsize=(5.55,5), colorbar= "blue")
        plt.show()
        accuracy = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='accuracy')
        print("Accuracy: %0.5f (+/- %0.5f)" % (accuracy.mean(), accuracy.std() * 2))
        precision = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='precision')
        print("Precision: %0.5f (+/- %0.5f)" % (precision.mean(), precision.std() * 2))
        recall = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='recall')
        print("Recall: %0.5f (+/- %0.5f)" % (recall.mean(), recall.std() * 2))
        f = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='f1')
        print("F-measure: %0.5f (+/- %0.5f)" % (f.mean(), f.std() * 2))

# apply_random_forest(x_train_list,y_train_list,x_test_list,y_test_list)

from sklearn.naive_bayes import GaussianNB
def apply_gaussian_native_bias(x_train_list,y_train_list,x_test_list,y_test_list):
    for i in range(4):
        clf=GaussianNB()
        clf.fit(x_train_list[i], y_train_list[i].astype(int))
        Confusion_Matrix=metrics.confusion_matrix(y_test_list[i],clf.predict(x_test_list[i]))
        plot_confusion_matrix(Confusion_Matrix,class_names=['Normal', 'Attack'],figsize=(5.55,5), colorbar= "blue")
        plt.show()
        accuracy = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='accuracy')
        print("Accuracy: %0.5f (+/- %0.5f)" % (accuracy.mean(), accuracy.std() * 2))
        precision = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='precision')
        print("Precision: %0.5f (+/- %0.5f)" % (precision.mean(), precision.std() * 2))
        recall = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='recall')
        print("Recall: %0.5f (+/- %0.5f)" % (recall.mean(), recall.std() * 2))
        f = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='f1')
        print("F-measure: %0.5f (+/- %0.5f)" % (f.mean(), f.std() * 2))
# apply_gaussian_native_bias(x_train_list,y_train_list,x_test_list,y_test_list)

from sklearn.neighbors import KNeighborsClassifier
# 
def apply_k_nearest_neighbour(x_train_list,y_train_list,x_test_list,y_test_list):
    for i in range(4):
        clf = KNeighborsClassifier()
        clf.fit(x_train_list[i], y_train_list[i].astype(int))
        Confusion_Matrix=metrics.confusion_matrix(y_test_list[i],clf.predict(x_test_list[i]))
        plot_confusion_matrix(Confusion_Matrix,class_names=['Normal', 'Attack'],figsize=(5.55,5), colorbar= "blue")
        plt.show()
        accuracy = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='accuracy')
        print("Accuracy: %0.5f (+/- %0.5f)" % (accuracy.mean(), accuracy.std() * 2))
        precision = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='precision')
        print("Precision: %0.5f (+/- %0.5f)" % (precision.mean(), precision.std() * 2))
        recall = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='recall')
        print("Recall: %0.5f (+/- %0.5f)" % (recall.mean(), recall.std() * 2))
        f = cross_val_score(clf, x_test_list[i], y_test_list[i], cv=10, scoring='f1')
        print("F-measure: %0.5f (+/- %0.5f)" % (f.mean(), f.std() * 2))
apply_k_nearest_neighbour(x_train_list,y_train_list,x_test_list,y_test_list)
