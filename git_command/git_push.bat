cd /d D:\Jenkins\jobs\testGitJobA\workspace\python_read_and_write_config_file
ssh-agent bash
ssh-add "C:\Users\Administrator\.ssh\id_rsa"
git push origin master
git branch
git checkout master
git add .
git commit -m "modify ini"
git push origin master