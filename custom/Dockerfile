FROM scratch
ADD simpleHttpd.linux /simpleHttpd

ADD /exp/ /exp/

EXPOSE 8080 443
ENTRYPOINT ["/simpleHttpd"]
