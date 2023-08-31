# Secure-File-Sharing
Code for our startup we closed , Varency.com a secure file sharing service uses gitactions for cicd 
along with that azure blob and s3 buckets for storing files 

Code realted to files/folder storage can be found in content dir 
Code related to general auth is in files , contains tenant , user , plan info
Code related to sync from google drive , one drive can be found in - /ftp 


This backend implements major functionality to support file downloading / uploading / syncing over azure blobs (can easily be migrated to s3)
Downloading code is majorly my written code to allow downloads to users above 1tb by streaming zip on the fly (the zip is built in chunks and chunks are streamed)

Most of the code can be refactored like user fetching and downloading and if someone can do that props :P


