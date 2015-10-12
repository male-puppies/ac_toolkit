src = nxjson.c auth_main.c
header = nxjson.h auth.h
all:auth_tool 

auth_tool:$(src) $(header) 
	$(CC) $(src) -o auth_tool 
	$(STRIP) auth_tool
.PHONY : clean

clean:
	rm -f *.o
	rm -f auth_tool  
