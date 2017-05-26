#!/bin/bash
# SAMBA is_known_pipename() vulnerability checker and patcher
# more info: CVE 2017-7494

function check_root_privileges {
if [[ $EUID != 0 ]] ; then
  echo "WARNING: We are not root so we will not be able to correct vulnerability if found"
  echo "Please call me from a root shell or using sudo"
  exit
fi
}

function get_package_type {
  yum &> /dev/null && export OS="RPM" || apt-get &> /dev/null && export OS="DEB"
}


function getsambaversion {
sambaroute=$(which samba)
if [[ $? == 1 ]]; then echo "SAMBA seems not installed in this system. Nothing to do here o_O!"; exit; fi
echo "SAMBA found in ${sambaroute}. Checking its version..."
sambaversionstring=$(samba -V | cut -d" " -f 2 | cut -d"-" -f1) # cut here and there to isolate the numbers...
echo "Version seems to be ${sambaversionstring}"
# now we assign major, minor and revision numbers to separate vars
# (yeah, I know, there are more efficient ways of doing this than using echo and cut, but this is the most backwards compatible!!)
export sambamajor="$(echo $sambaversionstring | cut -d"." -f 1)"
export sambaminor="$(echo $sambaversionstring | cut -d"." -f 2)"
export sambarev="$(echo $sambaversionstring | cut -d"." -f3)"
}

function performupgrade {
get_package_type
    case OS in
    "DEB")
      apt-get update && apt-get install --only-upgrade samba && echo "Samba upgrade finished :)" || echo "Something went wrong! Could not automatically upgrade samba :("
      ;;
    "RPM")
      yum update samba && echo "Samba upgrade finished :)" || echo "Something went wrong! Could not automatically upgrade samba :("
      ;;
    esac
}

function performcheck {
# Samba versions from 3.5.0 onwards are vulnerable
# Samba 4.6.4, 4.5.10 and 4.4.14 have been issued as security releases to correct the defect
# major version 3 && minor version > 4  == vulnerable and no official security released
# major version 4 && minor version < 4  == vulnerable and no official security released 
# major version 4 && minor version = 4  && rev < 14 == vulnerable
# major version 4 && minor version = 5  && rev < 10 == vulnerable
# major version 4 && minor version = 6  && rev < 4  == vulnerable
# rest == safe
# Versions reporting as "4.3.11" could be patched or not

if [[ ( $sambamajor -eq 3 && $sambaminor -gt 4 ) || \
      ( $sambamajor -eq 4 && $sambaminor -lt 4 ) || \
      ( $sambamajor -eq 4 && $sambaminor -eq 4 && $sambarev -lt 14 ) || \
      ( $sambamajor -eq 4 && $sambaminor -eq 5 && $sambarev -lt 10 ) || \
      ( $sambamajor -eq 4 && $sambaminor -eq 6 && $sambarev -lt 4  ) ]]; then
  # vulnerable version 
  echo "The SAMBA version in this computer most likely (unless some specific security patches manually applied recently) is amongst the affected." 
  echo "If you are certain that no security patches and no SAMBA package updates have been performed recently, please do one of the following:"
  echo " a) [EASIEST] Upgrade SAMBA version. Centos, RHEL, Debian and Ubuntu have issued package updates to address the issue already."
  echo " b) [MEDIUM] disable named pipes in smb.conf"
  echo " c) [ADVANCED] patch a tarball of SAMBA sources, rebuild and reinstall"
  echo " d) [MOST INTELLIGENT] better remove SAMBA from the system and choose an alternative to share your files though the Internet ;)"
  echo
  echo "If your GNU/Linux distro es RHEL/CentOS/Debian/Ubuntu/Derivative, I can do a) for you"
  echo "(that is, updating the SAMBA package for you if you want)."
  echo -n "Try to do it now? y/n:"
  read answer
  case answer in
  Y|y)
    performupgrade
    ;;
  *)
    echo "OK. Not doing anything. Suit yourself..."
  ;;
  esac
else
  echo "System seems to have a version of SAMBA with no CVE 2017-4787 vulnerability. Yay! :)"
fi
}

## MAIN () ##
# check_root_privileges # not necessary yet, patching not implemented
getsambaversion
performcheck
exit
