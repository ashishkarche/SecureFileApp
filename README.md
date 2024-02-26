# Secure File Storage on Cloud using hybrid cryptography & multiparty Method

1. `encryption/Decryption Algorithm ` - AES, DES, RC6, SHA5
   [Click to see explanation..](https://chat.openai.com/share/d4c200ff-e7d9-451e-aa48-9c005a703ec9)

2. `Multiparty Method` -

### The Three Most Common Types of Homomorphic Encryption

Encrypted data can be stored safely or transferred to a third party for analysis. Depending on the type of homomorphic encryption, certain processes are possible.

##### `a. Partial homomorphic encryption`: This method of encryption can perform one type of operation on encrypted data. For example, this type of encryption would allow data to be either added or multiplied, not both. The obvious drawback is that only one type of operation is possible.

##### `b. Somewhat homomorphic encryption`: This method of encryption can perform more than one type of operation. Data encrypted this way could be added and multiplied, but there is a limit to the number of operations that can be accomplished.

##### `c. Fully homomorphic encryption`: With this method of encryption, more than one type of secure computation can be performed. Additionally, there is no limit to the number of operations that can be performed.


3. `Code Language & server` - Java & Xampp Server

4. `How To Run This Code` -

   ##### Step 1 -

   Download Xampp server - [click to download xampp server..](https://www.apachefriends.org/download.html)

   ##### Step 2 -

   add MySql drive dependencies in your `pom.xml` & sync `pom.xml` (if dependencies already sync then no need to do `step 2` , we can direcly go on `step-3`).

   ```xml
   <dependencies>
    <!-- https://mvnrepository.com/artifact/mysql/mysql-connector-java -->
    <dependency>
      <groupId>mysql</groupId>
      <artifactId>mysql-connector-java</artifactId>
      <version>8.0.33</version>
    </dependency>
   </dependencies>
   ```

##### Step 3 -

just import downloaded database to xampp server, link is given ![Download Database](./filedatabase.sql).

##### Step 4 -

Tutorial for importing sql database to xampp server -[Click to see video..! ](https://youtu.be/2ynKAAt1G4Y?si=kOkDHDXhBy8_zw0Q)

##### Step 5 -

Run this command

```java
cd src\main\java\com\securefile
```

```java
javac *.java
```

```java
java Main.java
```
