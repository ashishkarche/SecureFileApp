# Secure File Storage on Cloud using hybrid cryptography & multiparty Method

1. `Algorithm encryption/Decryption` - AES, DES, RC6, SHA5
   [Algorrithm Explanation](https://chat.openai.com/share/d4c200ff-e7d9-451e-aa48-9c005a703ec9)

2. `Multiparty Method` -

### The Three Most Common Types of Homomorphic Encryption

Encrypted data can be stored safely or transferred to a third party for analysis. Depending on the type of homomorphic encryption, certain processes are possible.

##### `Partial homomorphic encryption`: This method of encryption can perform one type of operation on encrypted data. For example, this type of encryption would allow data to be either added or multiplied, not both. The obvious drawback is that only one type of operation is possible.

##### `Somewhat homomorphic encryption`: This method of encryption can perform more than one type of operation. Data encrypted this way could be added and multiplied, but there is a limit to the number of operations that can be accomplished.

##### `Fully homomorphic encryption`: With this method of encryption, more than one type of secure computation can be performed. Additionally, there is no limit to the number of operations that can be performed.

#### An Example Of Multiparty Encryption

![Example](src/main/resources/image/1.png)
![Example](src/main/resources/image/2.png)
![Example](src/main/resources/image/3.png)


3. `Code Language & server` - Java & Xampp Server

4. `How To Run This Code` -

   ##### Step 1 -

   Download Xampp server - [click to download xampp server..](https://www.apachefriends.org/download.html)

   ##### Step 2 -

   add Google Cloud dependencies in your pom.xml & sync pom.xml (if dependencies already sync then no need to do step 1 , you can direcly go on step-2)

   ```xml
   <dependencies>
    <!-- https://mvnrepository.com/artifact/mysql/mysql-connector-java -->
    <dependency>
      <groupId>mysql</groupId>
      <artifactId>mysql-connector-java</artifactId>
      <version>8.0.33</version>
    </dependency>
   ```

  </dependencies>
   ```

##### Step 3 -

Create sql data base by name `filedatabase` (if database is alreay created then no need to create database) 
or
just import created database to xampp server, link is given in `step 4`.

```sql
-- Create the database
CREATE DATABASE filedatabase;

-- Use the newly created database
USE filedatabase;

-- Create a table to store uploaded files
CREATE TABLE uploaded_files (
file_id INT AUTO_INCREMENT PRIMARY KEY,
file_name VARCHAR(255) NOT NULL,
file_data LONGBLOB NOT NULL
);

-- Create a table to store encrypted files
CREATE TABLE encrypted_files (
file_id INT AUTO_INCREMENT PRIMARY KEY,
file_name VARCHAR(255) NOT NULL,
encrypted_data LONGBLOB NOT NULL
);
```

##### Step 4 -

Tutorial for importing sql database to xampp server -[Click to see video ! ](https://youtu.be/ug-bj93_S_M?si=t2negUBl3czTE0Ah)

##### Step 5 -

Run this command

```java
cd src\main\java\com\securefile
```

```java
javac *.java
```

```java
java Main
```
