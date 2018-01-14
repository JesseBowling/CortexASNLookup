This is an analyzer for [Cortex](https://github.com/CERT-BDF/Cortex/blob/master/README.md). It will do IP address lookups against the Shadowserver BGP-IP Lookup service.

To install, place these files in a new directory (such as "ASNLookup") under your Cortex Analyzers directory.

Next, add a configuration stanza under the Cortex application.conf file, like this:

<pre>
analyzer {
  # Absolute path where you have pulled the Cortex-Analyzers repository.
  path = "/analyzers/Cortex-Analyzers/analyzers"

...

  # Analyzer configuration
  config {
    # ASNLookup: this analyzer needs no additional config
    ASNLookup {
    }
    
...

</pre>
Please report any issues or feature requests here!
