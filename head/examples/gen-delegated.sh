# This is a very simplified example that may be used as a starting point
# to generate the list of reverse delegations. A simple awk script could
# be used to extract information on reverse delegations from a BIND
# reverse zone file.

awk '/^[0-9.]+[ \t]+(IN[ \t]+)?NS/ { print $1 }' my-hosts-v4-rev >delegated4.txt
awk '/^[[:xdigit:].]+[ \t]+(IN[ \t]+)?NS/ { print $1 }' my-hosts-v6-rev >delegated6.txt

# The generated files can be used in router2dns.conf as
# reverse-zone {
#   ...
#   delegated {
#     name-list-file delegated4.txt;
#   }
# }
