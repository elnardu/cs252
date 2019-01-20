## compare_states.py
Compares the allocator state of the testing program to the allocator state of your program.

### Usage
1. Put compare_states.py file into your lab1-src directory
   - `wget https://raw.githubusercontent.com/elnardu/cs252/master/lab1-tools/compare_states.py`
2. `pip3 install wheel frida-tools`
3. `python3 compare_states.py test_name`
   - Please use `-s n`/`--skip n` option for large testcases (test_simple5, test_simple6)
      - that will skip processing of the first n malloc/free calls
   - **Comment out all your printfs**

Recommended `-s` values for test_simple5:
- 0
   - Covers initial state
   - Wait till it finishes 50-100 states
- 9999
   - Covers everything else
   - Usually where your problems are


### Screenshot
![](https://raw.githubusercontent.com/elnardu/cs252/master/lab1-tools/screenshot1.png)
