FROM scratch
ADD simpleHttpd.linux /simpleHttpd

EXPOSE 8080 443
ENTRYPOINT ["/simpleHttpd"]
