This is an analyzer for [Cortex](https://github.com/CERT-BDF/Cortex/blob/master/README.md). It will do IP address lookups against the packetmail.net (Punch++) IP reputation service.

To install, place these files in a new directory (such as "ASNLookup") under your Cortex Analyzers directory.

Next, add a configuration stanza under the Cortex application.conf file, like this:

<pre>
analyzer {
  # Absolute path where you have pulled the Cortex-Analyzers repository.
  path = "/analyzers/Cortex-Analyzers/analyzers"

...

  # Analyzer configuration
  config {
    # Cortex-IPrep: this analyzer needs your API key for Packetmail.net
    ASNLookup {
      key = "YOUR_PACKETMAIL_API_KEY"
    }
    
...

</pre>
Please report any issues or feature requests here!
