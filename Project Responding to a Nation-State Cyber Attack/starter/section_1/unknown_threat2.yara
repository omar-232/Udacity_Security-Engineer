rule tmplog {
    meta:
        Author = "@Omar"
        Description = "The rule detects tmplog bash script"
    strings:
        $path = "/home/ubuntu/Downloads/"
        $name = "cpu" nocase
        $port = "7777"
        $cpu = "cpu-usage" nocase
    condition:
        all of them
} 