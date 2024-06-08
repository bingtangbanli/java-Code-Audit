# java代码审计
## 一、sql注入
1、通过一些关键字可以定位到SQL语句附近

```java
Statement
createStatement
PrepareStatement
like '%${
in (${
select
update
insert
```

### （一）、JDBC的SQL注入
#### 1、常规漏洞
实操--搭建springboot

<img width="794" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/b09b9e0e-6afc-4ed4-aefd-154174bdbd60">
<img width="791" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/4f252ca1-3b58-439c-84c5-0085a45465fd">

配置数据库

<img width="795" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/c691650a-2816-44a6-8688-56ffe18f4b5f">

打开 src/main/resources/application.properties 配置文件，将以下数据库连接信息添加至配置中

```
#访问端口号
server.port=7070
#数据库连接信息
spring.datasource.url=jdbc:mysql://localhost:3306/java_sec-code?AllowPublicKeyRetrieval=true&useSSL=false&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=root
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
```
<img width="1400" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/e8424abe-a179-4fcf-9d3a-2bf87917cc40">

在 src\main\java\com\example\demo\jdbcinjection 下新建一个名为 JdbcDynamicController 的 Java Class。
```
package com.example.sql.jdbc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.*;

@RestController
@RequestMapping("/jdbcsql")
public class JdbcDynamicController {
    private static String driver = "com.mysql.cj.jdbc.Driver";
    //使用的是MySQL数据库的JDBC驱动，其类名是 "com.mysql.cj.jdbc.Driver"。这个驱动类负责与MySQL数据库建立连接。
    //用于从配置文件中读取属性值
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String user_name;
    @Value("${spring.datasource.password}")
    private String password;

    @RequestMapping("/dynamic")
    public String jdbcdynamic(@RequestParam("id") String id) throws ClassNotFoundException, SQLException {
        StringBuilder result = new StringBuilder();
        Class.forName(driver);
        Connection conn = DriverManager.getConnection(url, user_name, password);
        Statement statement = conn.createStatement();
        String sql = "select * from user where user_id = '" + id + "'";
        ResultSet rs = statement.executeQuery(sql);
        //遍历结果集
        while (rs.next()) {
            String rsUsername = rs.getString("user_name");
            String rsPassword = rs.getString("password");
            String info = String.format("%s: %s\n", rsUsername, rsPassword);
            result.append(info);
        }
        rs.close();
        conn.close();
        return result.toString();



    }
}
```

<img width="794" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/2b29dedf-a768-49d0-b1ff-d69c853af360">

测试      
```
http://127.0.0.1:7070/jdbcsql/dynamic?id=3
```

<img width="686" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/b575cb82-e798-41b8-b6b9-90ecf08ce4a7">
<img width="688" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/226677b2-447b-4336-ae04-3337c3ddde22">

漏洞修复

在 src\main\java\com\example\demo\jdbcinjection 下新建一个名为 JdbcPrepareStatement 的 Java Class

```java
package com.example.sql.jdbc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.*;

@RestController
@RequestMapping("/jdbcsqld")
public class JdbcPrepareStatement {
    private static String driver = "com.mysql.cj.jdbc.Driver";
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String user_name;
    @Value("${spring.datasource.password}")
    private String password;

    @RequestMapping("/preSec")

    public String jdbcPreSec(@RequestParam("id") String id) throws ClassNotFoundException, SQLException {
        if (id == null || id.trim().isEmpty()) {
            return "Invalid id";
        }

        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection conn = DriverManager.getConnection(url, user_name, password);
            String sql = "select * from user where user_id=?";
            PreparedStatement preparedStatement = conn.prepareStatement(sql);
            preparedStatement.setString(1, id);

            ResultSet rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String resUsername = rs.getString("user_name");
                String resPassword = rs.getString("password");
                String info = String.format("%s: %s\n", resUsername, resPassword);
                result.append(info);
            }
        } catch (Exception e) {
            // Log or handle the exception here
            return "Error occurred: " + e.getMessage();
        }

        return result.toString();
    }

    @RequestMapping("/preNot")
    public String jdbcPreNot(@RequestParam("id") String id) throws SQLException, ClassNotFoundException {
        StringBuilder result = new StringBuilder();
        Class.forName(driver);
        Connection conn = DriverManager.getConnection(url, user_name, password);
        //还是直接进行了拼接 无效
        String sql = "select * from user where user_id = '" + id + "'";
        PreparedStatement preparestatement = conn.prepareStatement(sql);
        ResultSet rs = preparestatement.executeQuery();
        while (rs.next()) {
            String reUsername = rs.getString("user_name");
            String resPassword = rs.getString("password");
            String info = String.format("%s: %s\n", reUsername, resPassword);
            result.append(info);
        }
        rs.close();
        conn.close();
        return result.toString();

    }

}

```

正确的预编译代码效果：

```
http://127.0.0.1:7070/jdbcsqld/preNot?id=1%27or%201=1%23
```
<img width="841" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/1adf73a9-82ef-475f-945c-5d370d10641b">

错误的预编译代码效果：

```
http://127.0.0.1:7070/jdbcsqld/preSec?id=1%27or%201=1%23
```

<img width="808" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/2daf76ad-c596-4da2-a0c1-4079eead2ccd">

#### 2、order by注入

order by 语句用于对结果集进行排序。 order by 语句后面需要是字段名或者字段位 置。 在使用 PreparedStatement 预编译时，会将传递任意参数使用单引号包裹进而变为了字符串。 如果使用预编译方式执行 order by 语句，设置的字段名会被人为是字符串，而不再是字段名。 因此，在使用 order by 时，就不能使用 PreparedStatement 预编译了

新建一个名为 jdbcOrderby 的Java Class， 并键入以下代码

```java
package com.example.sql.jdbc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.*;

@RestController
@RequestMapping("/jdbcsqlorderby")
public class jdbcOrderby {
    private static String driver = "com.mysql.jdbc.Driver";
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String user_name;
    @Value("${spring.datasource.password}")
    private String password;
    @RequestMapping("/PreOrderby")
    public String jdbcOrderby(@RequestParam("id") String id) throws
            ClassNotFoundException, SQLException {
        StringBuilder result = new StringBuilder();
        Class.forName(driver);
        Connection conn = DriverManager.getConnection(url, user_name, password);
        String sql = "select * from user" + " order by " + id;
        PreparedStatement preparestatement = conn.prepareStatement(sql);
        ResultSet rs = preparestatement.executeQuery();
        while (rs.next()) {
            String reUsername = rs.getString("user_name");
            String resPassword = rs.getString("password");
            String info = String.format("%s: %s\n", reUsername, resPassword);
            result.append(info);
        }
        rs.close();
        conn.close();
        return result.toString();
    }
}

```
测试

```
http://127.0.0.1:7070/jdbcsqlorderby/PreOrderby?id=if(1=1,sleep(1),1)
```

<img width="919" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/35143a1d-2169-44d8-8697-c519b8f07720">

漏洞修复

```java
package com.example.sql.jdbc;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.sql.*;

@RestController
@RequestMapping("/jdbcsqlorderbysec")
public class jdbcOrderbysec {
    private static String driver = "com.mysql.jdbc.Driver";
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String user_name;
    @Value("${spring.datasource.password}")
    private String password;

    @RequestMapping("/PreOrderbysec")
    public String jdbcOrderby(@RequestParam("id") String id) {
        StringBuilder result = new StringBuilder();
        String sql = "select * from user order by ?";

        try (Connection conn = DriverManager.getConnection(url, user_name, password);
             PreparedStatement preparestatement = conn.prepareStatement(sql)) {

            preparestatement.setString(1, id);
            ResultSet rs = preparestatement.executeQuery();

            while (rs.next()) {
                String reUsername = rs.getString("user_name");
                String resPassword = rs.getString("password");
                String info = String.format("%s: %s\n", reUsername, resPassword);
                result.append(info);
            }

        } catch (SQLException e) {
            e.printStackTrace(); // or log the exception
            // Handle the SQL exception appropriately
            return "Error occurred: " + e.getMessage();
        }

        return result.toString();
    }
}


```

使用 `PreparedStatement`来安全地处理参数

<img width="870" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/dbafb023-b190-48a4-a44c-53f1afd7d038">

#### 3、like注入

```java
package com.example.sql.jdbc;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;
import java.sql.*;

@RestController
@RequestMapping("/jdbcsqllike")
public class jdbcsqllike {
    private static String driver = "com.mysql.jdbc.Driver";
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String user_name;
    @Value("${spring.datasource.password}")
    private String password;

    @RequestMapping("/vul")
    public String jdbclike(@RequestParam("id") String id) throws ClassNotFoundException, SQLException {
        StringBuilder result = new StringBuilder();
        Class.forName(driver);
        Connection conn = DriverManager.getConnection(url, user_name, password);

        // Vulnerable code using concatenated string
        String sql = "SELECT * FROM user WHERE user_name LIKE '%" + id + "%'";

        PreparedStatement preparestatement = conn.prepareStatement(sql);
        ResultSet rs = preparestatement.executeQuery();

        while (rs.next()) {
            String reUsername = rs.getString("user_name");
            String resPassword = rs.getString("password");
            String info = String.format("%s: %s\n", reUsername, resPassword);
            result.append(info);
        }

        rs.close();
        conn.close();
        return result.toString();
    }
}

```

测试

```
http://127.0.0.1:7070/jdbcsqllike/vul?id=d
```

<img width="726" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/d24baf30-e04d-4d14-ade9-de323ad287f9">


```
http://127.0.0.1:7070/jdbcsqllike/vul?id=a
```

<img width="634" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/96961ac0-33c9-4aa2-a968-7cb6ef3c0946">

漏洞修复
```
package com.example.sql.jdbc;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;
import java.sql.*;

@RestController
@RequestMapping("/jdbcsqllikesec")
public class jdbcsqllikesec {
    private static String driver = "com.mysql.jdbc.Driver";
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String user_name;
    @Value("${spring.datasource.password}")
    private String password;

    @RequestMapping("/secure")
    public String jdbclikeSecure(@RequestParam("id") String id) {
        StringBuilder result = new StringBuilder();

        try (Connection conn = DriverManager.getConnection(url, user_name, password)) {
            // Secure code using parameterized query
            String sql = "SELECT * FROM users WHERE user_name LIKE ?";
            try (PreparedStatement preparestatement = conn.prepareStatement(sql)) {
                preparestatement.setString(1, "%" + id + "%");
                ResultSet rs = preparestatement.executeQuery();

                while (rs.next()) {
                    String reUsername = rs.getString("user_name");
                    String resPassword = rs.getString("password");
                    String info = String.format("%s: %s\n", reUsername, resPassword);
                    result.append(info);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); // Log or handle the exception appropriately
            return "Error occurred: " + e.getMessage();
        }

        return result.toString();
    }
}

```
```
http://127.0.0.1:7070/jdbcsqllikesec/secure?id=a
```
<img width="585" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/71910765-686e-458d-ba4d-bf5aaab36fd5">
















