# docker_project

## 使用的版本
+ docker - v17.05.0-ce
+ dockerd - v17.06.0-dev
+ docker-containerd - v17.06.0-dev
+ docker-containerd-shim - v17.06.0-dev
+ docker-containerd-ctr - v17.06.0-dev
+ docker-runc - v17.06.0-dev
+ docker-init - v17.06.0-dev
+ docker-proxy - v17.06.0-dev

## remapping  注意事項
+ sudo grubby --args="namespace.unpriv_enable=1 user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
+ echo "user.max_user_namespaces=15000" >> /etc/sysctl.conf
+ sysctl -p
## remapping 限制
+ sharing PID or NET namespaces with the host (--pid=host or --network=host).
+ external (volume or storage) drivers which are unaware or incapable of using daemon user mappings.
+ Using the --privileged mode flag on docker run without also specifying --userns=host.

## image Vulnerability 注意事項
+ 開啟 9279 port && 重啟防火牆
    + firewall-cmd --zone=public --add-port=9279/tcp --permanent
    + firewall-cmd --reload
+ 在家目錄新建一個名為 Dockerfile 的資料夾
    + mkdir $HOME/Dockerfile
+  開啟兩個 container
    +  docker run -d --name db arminc/clair-db:2018-09-15(日期可修改)
    +  docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:v2.0.5
+ 要 run 的 container 要先執行 docker pull 把 image 下載下來

## 密碼驗證 注意事項
+ 原始密碼 ncsistproj2018
