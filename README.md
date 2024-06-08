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


