# **Exploiting Intermediate Value Leakage in Dilithium: A Template-Based Approach**

 

This is an artifact for the corresponding article accepted for CHES 2023. \
Find the paper at https://eprint.iacr.org/2023/050
 

* __template__ : Notebooks & data sets for template
* __additional_materials__ : Number of signatures needed for the attack, majority vote, resolution
	* __c_materials__ : Filter, collect w_0 = 0

 

## Getting Started
### Environment Installation
---
Require Python >=3.11 \
Install ```pipenv install --python "path/to/python3.11"``` \
Activate ```pipenv shell```  
Require Sagemath >=9.5 set as a Jupyter Kernel \
To launch the notebooks ```jupyter notebook```
 

### Getting the data sets
---
Copy and unzip dataset.zip into template/dataset \
Download it from:  https://www.dropbox.com/scl/fo/8tqg64ze5zfr77pn8rgp8/h?dl=0&rlkey=h8vvmmyfr5jgxidty9n0pfkpo \
Alternatively, this can be done directly by running the bash script ```./download.sh``` (make sure to set the permissions before)
 

### Getting the C code
---

Download it from here: https://github.com/pq-crystals/dilithium \
Then, add the content of the C materials folder inside dilithium/ref (replace the existing Makefile with ours) \
This can be done directly by running the bash script ```./copy_files.sh``` (make sure to set the permissions before) 

### Recommended execution order
---

- For the template part: execute the notebooks in the provided order
- For the additional materials notebooks:
    - 3.5_nb_signatures attack.ipynb: Computes the number of signatures needed for the attack
    - 4.5_dilithium_resolution.ipynb: Solves for a potential t0 - s2, requires Sage
    - 4.5_majority_vote_evaluation.ipynb: Error Managment evaluation, requires Sage
    - Optional: 
        - To regenerate the file Dilithium2_sign_with_index_w0_to_0.rsp you can execute the C code PQCcollect_w0_to_0. \
          To compile it, go to the `dilithium/ref/` directory and run
        ```sh
        make PQCcollect_w0_to_0$ALG
        ```
        This produces the executable
        ```sh
        PQCcollect_w0_to_0$ALG
        ```
        where `$ALG` ranges over the parameter sets 2, 3, and 5.
        - To test the filter decribed in the paper, you can execute the C code PQCtest_filter.c as previously explained.
 

### License
---

This work is licensed under a
[Creative Commons Attribution 4.0 International License][cc-by].

[![CC BY 4.0][cc-by-image]][cc-by]

[cc-by]: http://creativecommons.org/licenses/by/4.0/
[cc-by-image]: https://i.creativecommons.org/l/by/4.0/88x31.png
See [LICENSE.txt](./LICENSE.txt)

The template notebooks are based on the scared python module https://gitlab.com/eshard/scared/-/blob/master/LICENSE
under LGPL V3 license.

This atifact uses the Dilithium reference implementation from https://github.com/pq-crystals/dilithium ,under Apache 2.0 License, as a submodule.
