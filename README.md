# Mythic_CLI
Golang code for the `mythic-cli` binary in Mythic. This binary provides control for various aspects of Mythic configuration.

## mythic-cli help

```
mythic-cli usage ( v 0.0.2 ):
  help
  mythic {start|stop} [service name...]
  c2 {start|stop|add|remove|list} [c2profile ...]
      The add/remove subcommands adjust the docker-compose file, not manipulate files on disk
        to manipulate files on disk, use 'install' and 'uninstall' commands
  payload {start|stop|add|remove|list} [payloadtype ...]
      The add/remove subcommands adjust the docker-compose file, not manipulate files on disk
        to manipulate files on disk, use 'install' and 'uninstall' commands
  config
      *no parameters will dump the entire config*
      get [varname ...]
      set <var name> <var value>
  database reset
  install 
      github <url> [branch name] [-f]
      folder <path to folder> [-f]
      -f forces the removal of the currently installed version and overwrites with the new, otherwise will prompt you
      * this command will manipulate files on disk and update docker-compose
  uninstall {name}
      (this command removes the payload or c2 profile from disk and updates docker-compose)
  status
  logs <container name>
  version
```

## Compilation

The binary distributed with Mythic is compiled with `go build -ldflags="-s -w" -o mythic-cli main.go` and then passed through `upx` with `upx --brute mythic-cli`. This is simply so that the standard 13MB Golang file is compressed down to a 2.5MB file for easier inclusion with the Mythic repo.

## Version

The current version of the `mythic-cli` code is `0.0.1`
