// The scanner supplies the basename explicitly. This is not a malware signature.
rule Course_Suspicious_Double_Extension {
    condition:
        filename matches /.+\.(pdf|doc|docx|txt|jpg|png|xlsx)\.(exe|scr|com|bat|cmd|ps1|vbs|js|lnk)$/i
}
