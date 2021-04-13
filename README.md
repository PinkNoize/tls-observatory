#

Update dataset URLs

# Setting up the mongoDB database

## Start the mongoDB database using Docker
1. Install Docker
2. Change the password in docker-compose.yml
3. Start the mongoDB server
    
    ```
    $ cd tls-observatory
    $ sudo docker-compose up -d
    ```
    This will setup a database that will listen on 127.0.0.1:27017

    NOTE: If you want to stop the database but still keep the data, run `docker-compose stop`.
    
    `docker-compose down` will delete your database.

4. Connect to the server to test
    
    ```
    $ mongo --username root
    ```