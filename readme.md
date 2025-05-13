# PFortifier

This is the code for the paper: [PFORTIFIER: Mitigating PHP Object Injection through Automatic Patch Generation](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a918/26hiU0IeM3S).  
The presentation of our work was part of the IEEE S&P 2025 event.  
Please cite the above paper if you use our code.  
The code is released under the GPLv3.

## Introduction

* Automated PHP POP chain discovery
* Automatic patch generation
* Neo4j graph query-assisted discovery
* Fixed parsing issues with new PHP syntax in phply
* ~~Payload auto-generation (deprecated)~~

## Installation

* Install Python
* Install py2neo: `pip install py2neo`
* (Optional) Install Neo4j and set the password to "password"

## Reproducing the Results in the Paper

* Download the PHP code dataset from [<https://github.com/CyanM0un/PFortifier_DataSet>]. Keep the default configurations in `config.py`, set the target code path (`php_prog_root`), and run `Main.py`.
* After scanning and patch generation, results will be saved under the `result` directory:
  * `pop_chains.json`: Discovered POP chains
  * `patch.json`: Generated patches for the POP chains
  * `patch_collect.json`: De-duplicated patches for manual review
  * `unable2patch_entry.json`: Entry points where suggestions are generated instead of direct patches

## Usage in Real-World Scenarios

* Configure `config.py` and run `Main.py`

### Hyperparameter Descriptions

* `php_prog_root`: Root directory of the PHP program
* `gc_switch`: Enable garbage collection (reduces memory usage but slows scanning)
* `patch_generate`: Enable patch generation
* `graph_gen`: Enable Neo4j graph database collection
* `use_pm_summary`: Enable summary acceleration mode (recommended; see paper for details)
* `skip_overdetected`: Skip over-detected chains (filters chains with identical entry-sink pairs in PM mode)
* `filter_sink`: Record each entry-sink pair only once
* `use_cache`: Enable cache for subsequent scans on the same codebase
* `exclude_die_wakeup`: Exclude classes with `die()` in `__wakeup`
* `entry_func_li`: Entry functions (e.g., `__destruct`)
* `max_pm_length`: Maximum PM chain length (PM mode only)
* `max_normal_length`: Maximum chain length (all methods/functions). Tip: Set one to 999999 and limit the other
* `each_entry_early_stop_num`: Maximum chains per entry (prevents excessive logging)
* `entry_depth`: Entry chain depth (controls initial chain segments treated as entries)
* `early_stop_num`: Global maximum chain count (stops logging if exceeded)

### Hyperparameter Best Practices

Recommended configurations for different goals:

* **POP Chain Discovery**:
  * `each_entry_early_stop_num`: 999999
  * `entry_depth`: 1-3 (adjust based on codebase size)
  * `early_stop_num`: 3000+
* **Patch Generation**:
  * `each_entry_early_stop_num`: 5
  * `entry_depth`: 3
  * `early_stop_num`: 1000
  * Disable PM summary for large frameworks

General Tips:

* `max_pm_length` < 6 (balances coverage and speed)
* `max_normal_length` = 9 (faster for large frameworks)
* Deeper `entry_depth` enhances entry discovery for patching

### Additional Tips

* Comment out irrelevant PHP code as needed
* Neo4j queries may reveal more chains than direct scanning
* For frameworks with many sinks, disable PM summary and set `each_entry_early_stop_num` = 5

### Neo4j Queries

Find deserialization chains of length 3-5:

```cypher
MATCH p=(m1:Method{MethodName:"__destruct"})-[*3..5]->(m2{IsSink:TRUE}) RETURN p LIMIT 25
```

## Implementation Notes

* PFortifier preserves case sensitivity for classes/namespaces to align with `vendor/autoload.php` behavior, despite PHP's case insensitivity.

## License

[LICENSE](/COPYING)
