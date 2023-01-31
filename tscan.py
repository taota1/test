import threading
import time

import requests
import urllib3

urllib3.disable_warnings()


# actuator
def actuator_scan(host):
    path_list = ['/env', '/actuator/env', '/api/actuator/env']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200 and req.headers[
                'Content-Type'] == 'application/vnd.spring-boot.actuator.v3+json':
                print("可能存在问题：" + url)
                return url

        except:
            continue


# alibaba druid，常见弱口令，admin/123456
def alibaba_druid_scan(host):
    path_list = ['/druid/index.html', '/actuator/druid', '/druid']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200 and "namespace" in req.text:
                print("可能存在问题：" + url)
                return url

        except:
            continue


# apache druid
def apache_druid_scan(host):
    url = host.strip("/") + '/unified-console.html'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200 and "Apache Druid" in req.text:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# graphql
def graphql_scan(host):
    path_list = ["/graphql", '/graphql/console']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if 'graphql' in req.text and req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# 文件写入权限  put
def put_scan(host):
    url = host.strip("/") + '/test.txt'
    payload = "testaa,hello world"
    try:
        requests.put(url, data=payload, verify=False, timeout=1)
        req = requests.put(url, data=payload, verify=False, timeout=1)

        if req.status_code == 200 and 'testaa' in req.text:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# .git
def git_scan(host):
    url = host.strip("/") + '/.git/config'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200 and 'repositoryformatversion' in req.text:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# CISCO ASA设备任意文件读取漏洞(CVE-2020-3452)
def cisco_vpn_scan(host):
    url = host.strip(
        "/") + '/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200 and '@cisco.com' in req.text:
            print("可能存在CISCO ASA设备任意文件读取漏洞(CVE-2020-3452)：" + url)
            return url
    except:
        pass


# swagger
def swagger_scan(host):
    path_list = ['/swagger-ui.html', '/api/v2/api-docs', '/api/api-docs', '/api-docs', '/v2/api-docs', "/v3/api-docs",
                 '/doc.html', '/docs', '/rest/openapi.json','/swagger.yaml', '/swagger.json', '/v2/swagger.json', '/v2/swagger.json']
    for path in path_list:
        url = host.strip("/") + path.strip()

        try:
            req = requests.get(url, verify=False, timeout=1)

            if 'swagger' in req.text and req.status_code == 200:
                print("可能存在问题：" + url)
                return url

        except:
            continue


# other
def other_scan(host):
    url = host.strip("/")
    try:
        req = requests.get(url, verify=False, timeout=1)
        # spring eureka   
        if req.status_code == 200 and 'Instances currently registered with Eureka' in req.text:
            print("可能存在问题：" + url)
            return url

    except:
        pass


# nacos 默认口令：nacos/nacos,https://blog.csdn.net/u012921921/article/details/112787746
def nacos_scan(host):
    url = host.strip("/") + '/nacos'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200 and '<title>Nacos</title>' in req.text:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# es
def es_scan(host):
    """
 
    """
    path_list = [':9200/_cat/indices', ':9200/_river/_search', ':9200/_nodes']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# docker api
def docker_api_scan(host):
    url = host.strip("/") + ':2375/version'
    # print(url)
    try:

        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# Docker Registry未授权
def docker_registry_scan(host):
    url = host.strip("/") + ':5000/v2'
    # print(url)
    try:

        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# Kibana
def kibana_scan(host):
    path_list = [':5601/', '/app/kibana#', ':5601/app/kibana#/']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# jenkins
def jenkins_scan(host):
    """
    https://c2.zhuzher.com/jenkins/script
    println "ls /tdata/home/".execute().text

    """
    path_list = [':8080/manage', ':8080/script', '/script']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200 and "println" in req.text:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# CouchDB
def CouchDB_scan(host):
    path_list = [':5984', ':5984/_utils/#login', ':5984/_config']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200 and "println" in req.text:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# weblogic
def Weblogic_scan(host):
    url = host.strip("/") + ':7001/console/css/%252e%252e%252fconsole.portal'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# HadoopYARN 未授权访问
def Hadoop_scan(host):
    url = host.strip("/") + ':8088/cluster'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# JBoss
def JBoss_scan(host):
    path_list = [':8080/jmx-console/', ':8080/jbossws/']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# Apache Spark
def Spark_scan(host):
    path_list = [':8080', ':8081']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200 and "park" in req.text:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# Active MQ 默认密码：admin/admin
def ActiveMQ_scan(host):
    url = host.strip("/") + ':8161/admin/'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# Jupyter Notebook
def JupyterNotebook_scan(host):
    url = host.strip("/") + ':8888/tree?'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# kubelet_scan
def kubelet_scan(host):
    path_list = [':8080/ui', ':10250/pods']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# Zabbix
def Zabbix_scan(host):
    url = host.strip("/") + ':8080/zabbix/setup.php'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# RabbitMQ_scan 弱口令guest/guest
def RabbitMQ_scan(host):
    path_list = [':15692', ':25672', ':15672']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# solr
def Solr_scan(host):
    url = host.strip("/") + '/solr/admin'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass


# Harbor任意账户注册
def Harbor_scan(host):
    url = host.strip("/") + '/harbor/sign-in'
    # print(url)
    try:
        req = requests.get(url, verify=False, timeout=1)

        if req.status_code == 200:
            print("可能存在问题：" + url)
            return url
    except:
        pass

# graphql
def env_scan(host):
    path_list = ["/.credentials", '/.env']
    for path in path_list:
        url = host.strip("/") + path.strip()
        # print(url)
        try:
            req = requests.get(url, verify=False, timeout=1)

            if 'graphql' in req.text and req.status_code == 200:
                print("可能存在问题：" + url)
                return url
        except:
            continue


# 扫描函数
# t0do：https://mp.weixin.qq.com/s/BIY7Jq5T6yV2TkTzSuhHSA

def t_scan(url):
    vul_url = []
    try:
        req0 = requests.get(url.strip(), verify=False, timeout=2)
        if req0.url:
            print("正在扫描：" + url)
            # print(threading.current_thread().getName(),"正在扫描：" + url,end="")
            vul_url.append(swagger_scan(url.strip()))
            vul_url.append(env_scan(url.strip()))
            vul_url.append(actuator_scan(url.strip()))
            vul_url.append(alibaba_druid_scan(url.strip()))
            # vul_url.append(apache_druid_scan(url.strip()))
            # vul_url.append(graphql_scan(url.strip()))
            vul_url.append(git_scan(url.strip()))
            # vul_url.append(cisco_vpn_scan(url.strip()))
            # vul_url.append(put_scan(url.strip()))
            # vul_url.append(nacos_scan(url.strip()))
            # vul_url.append(other_scan(url.strip()))
            # vul_url.append(es_scan(url.strip()))
            # vul_url.append(kibana_scan(url.strip()))
            # vul_url.append(jenkins_scan(url.strip()))
            # vul_url.append(docker_api_scan(url.strip()))
            # vul_url.append(docker_registry_scan(url.strip()))
            # vul_url.append(CouchDB_scan(url.strip()))
            # vul_url.append(Weblogic_scan(url.strip()))
            # vul_url.append(Hadoop_scan(url.strip()))
            # vul_url.append(JBoss_scan(url.strip()))
            # vul_url.append(ActiveMQ_scan(url.strip()))
            # vul_url.append(kubelet_scan(url.strip()))
            # vul_url.append(JupyterNotebook_scan(url.strip()))
            # vul_url.append(Zabbix_scan(url.strip()))
            # vul_url.append(RabbitMQ_scan(url.strip()))
            # # vul_url.append(Harbor_scan(url.strip()))
            # vul_url.append(Spark_scan(url.strip()))
        else:
            print("扫描失败：" + url)
    except:
        print("扫描失败：" + url)

    # sentry SSRF\zeppelin\ActiveMQ\zabbix\Zimbra\InfluxDB

    return vul_url


def thread_scan(t):
    with open('./domains.txt', encoding='utf-8') as f:
        urls = f.readlines()
        num_scan = len(urls) // t

    for i in range(0, len(urls), num_scan):
        sublist = urls[i:i + num_scan]
        threading.Thread(target=start_scan, args=(sublist,)).start()


def start_scan(sublist):
    with open('./result.txt', mode='a') as f:
        # 开始扫描时间
        localtime = time.strftime("%Y-%m-%d %H:%M:%S ", time.localtime())
        f.write("startTime:-----------------------" + localtime + "----------------" + "\n")

        for url in sublist:
            vul_url_list = t_scan(url.strip())

            for uu in vul_url_list:
                if uu:
                    f.write(uu + '\n')

        # 扫描完毕时间
        localtime = time.strftime("%Y-%m-%d %H:%M:%S ", time.localtime())
        f.write("endTime:-----------------------" + localtime + "------------------" + "\n\n")


if __name__ == '__main__':
    # 定义线程
    num_threads = 20
    thread_scan(num_threads)
