# Secure File Storage on Cloud using hybrid cryptography with multiparty encryption FHE

1. `Encryption/Decryption Algorithm ` - AES, DES, RC6, SHA5
   [Click to see explanation..](https://chat.openai.com/share/d4c200ff-e7d9-451e-aa48-9c005a703ec9)

2. `Multiparty Method` -

### Multiparty encryption with FHE -

Encrypted data can be stored safely or transferred to a third party for analysis. Depending on the type of homomorphic encryption, certain processes are possible.

##### ` Fully homomorphic encryption`: With this method of encryption, more than one type of secure computation can be performed. Additionally, there is no limit to the number of operations that can be performed.

3. `Code Language & server` - Java & Cloud Server

4. `How To Run This Code` -

   ##### Step 1 -

   Signup & connect to [cloud server](https://tidbcloud.com/) 

   ##### Step 2 -

   Add MySql drive & smpt protocol dependencies in your `pom.xml` & sync `pom.xml` (if dependencies already sync then no need to do `step 2` , we can direcly go on `step-3`).

   ```xml
   <dependencies>
    <!-- https://mvnrepository.com/artifact/mysql/mysql-connector-java -->
    <dependency>
      <groupId>mysql</groupId>
      <artifactId>mysql-connector-java</artifactId>
      <version>8.0.33</version>
    </dependency>

    <dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>javax.mail</artifactId>
    <version>1.6.2</version>
   </dependency>

   </dependencies>
   ```

##### Step 3 -

just import downloaded database to xampp server, link is given ![Download Database](./filedatabase.sql).

##### Step 4 -

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
