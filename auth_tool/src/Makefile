src = nxjson.c auth_main.c
all:auth_tool 

auth_tool: 
	$(CC) -g -fpic -shared  $(src)   -o auth_tool 
	$(STRIP) auth_tool
.PHONY : clean

clean:
	rm -rf *.o
	rm -f auth_tool  
