# from sklearn.cluster import AgglomerativeClustering

# from sklearn.ensemble import IsolationForest
# from sklearn.decomposition import PCA

# from server_utils import *
# import matplotlib.pyplot as plt

# colors = {0:'green', 1:'blue', 2:'red',3:'yellow', 4:'purple', 5:'brown',6:'pink',7:'olive',8:'cyan',9:'gray'}

# def jitter(arr):
#     stdev = .02*(max(arr)-min(arr))
#     return arr + np.random.randn(len(arr)) * stdev

# iforest=IsolationForest(contamination=0.25)
# df,features=create_df_file(file_log_file)
# bro_matrix=to_matrix.fit_transform(df[features],normalize=True) 
# features.append('score')
# iforest.fit(bro_matrix)
# df['score']=iforest.decision_function(bro_matrix)
# print(iforest.predict(bro_matrix))
# odd_df=df[features][iforest.predict(bro_matrix) == -1]
# odd_matrix=to_matrix.fit_transform(odd_df)

# # clustering = AgglomerativeClustering(n_clusters=6).fit_predict(odd_matrix)
# clustering=KMeans(n_clusters=6).fit_predict(odd_matrix)
# pca=PCA(n_components=2).fit_transform(odd_matrix)

# odd_df['x'] = pca[:, 0] 
# odd_df['y'] = pca[:, 1] 
# odd_df['cluster'] = clustering

# odd_df['jx'] = jitter(odd_df['x'])
# odd_df['jy'] = jitter(odd_df['y'])

# cluster_groups = odd_df.groupby('cluster')
# fig, axs = plt.subplots(1,1)
# for key, group in cluster_groups:  
#         group.plot(ax=axs, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])
#         print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
#         if 'score' in features:
#             top=group[features].sort_values(by='score', ascending=False).head()
#             print(top)
               
# plt.show()
string='aaaa'
