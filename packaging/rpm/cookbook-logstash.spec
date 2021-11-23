%global cookbook_path /var/chef/cookbooks/logstash/

Name: cookbook-logstash
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: Logstash cookbook to install and configure it in redborder environments

License: AGPL 3.0
URL: https://github.com/redBorder/cookbook-logstash
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%prep

%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}%{cookbook_path}
cp -f -r  resources/* %{buildroot}%{cookbook_path}
chmod -R 0755 %{buildroot}%{cookbook_path}
install -D -m 0644 README.md %{buildroot}%{cookbook_path}/README.md

%pre

%post
case "$1" in
  1)
    # This is an initial install.
    :
  ;;
  2)
    # This is an upgrade.
    su - -s /bin/bash -c 'source /etc/profile && rvm gemset use default && env knife cookbook upload logstash'
  ;;
esac
mkdir -p /share/logstash-rules

%files
%defattr(0755,root,root)
%{cookbook_path}
%defattr(0644,root,root)
%{cookbook_path}/README.md

%doc

%changelog
* Wed Nov 17 2021 Javier Rodriguez <javiercrg@redborder.com> - 1.0.3-1
- Vault pipeline enrichment

* Fri Oct 22 2021 Javier Rodriguez <javiercrg@redborder.com> - 1.0.2-1
- Netflow pipeline enrichment

* Tue Oct 19 2021 Javier Rodriguez <javiercrg@redborder.com> - 1.0.1-1
- Sflow pipeline enrichment

* Thu Jan 25 2018 Juan J. Prieto <jjprieto@redborder.com> - 1.0.0-1
- first spec version
