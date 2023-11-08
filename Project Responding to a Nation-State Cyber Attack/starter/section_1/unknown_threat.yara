rule ssh_one {
    meta:
        Author = "@Omar"
        Description = "The rule detects ssh one bash script"
    strings:
        $domain = "http://darkl0rd.com:7758"
        $name = "SSH-One"
        $script = "/tmp/$script"
    condition:
        all of them
} 