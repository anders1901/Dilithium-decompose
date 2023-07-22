# **Exploiting Intermediate Value Leakage in Dilithium: A Template-Based Approach**

 

This is an artifact for the corresponding article accepted for CHES 2023.

 

* __template__ : Notebooks & data sets for template
* __additional_materials__ : Number of signatures needed for the attack, majority vote, resolution
	* __c_materials__ : Filter, collect w_0 = 0

 

## Getting Started
### Environment Installation
---
Require Python >=3.11 \
Launch ```pipenv install``` \
Require Sagemath >=9.5

 

### Getting the data sets
---
Copy and unzip dataset.zip into template/dataset 
Download it from:  https://www.dropbox.com/scl/fo/8tqg64ze5zfr77pn8rgp8/h?dl=0&rlkey=h8vvmmyfr5jgxidty9n0pfkpo

 

### Getting the C code
---

Download it from here: https://github.com/pq-crystals/dilithium
Then, add the content of the C materials folder inside dilithium/ref (replace the makefile)

 

### License
---
See [LICENSE.txt](./LICENSE.txt)
