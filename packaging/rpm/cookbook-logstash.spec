%global cookbook_path /var/chef/cookbooks/logstash/
%global plugins_path /share/logstash-plugins/

Name: cookbook-logstash
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: Logstash cookbook to install and configure it in redborder environments

License: AGPL 3.0
URL: https://github.com/redBorder/cookbook-logstash
Source0: %{name}-%{version}.tar.gz
Source1: logstash-offline-plugins-7.4.2.zip

%define _unpackaged_files_terminate_build 0

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
mkdir -p %{buildroot}%{plugins_path}
cp -f $RPM_SOURCE_DIR/logstash-offline-plugins-7.4.2.zip %{buildroot}%{plugins_path}

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
if [ -f %{plugins_path}logstash-offline-plugins-7.4.2.zip ]; then
    /usr/share/logstash/bin/logstash-plugin install --no-verify file://%{plugins_path}logstash-offline-plugins-7.4.2.zip 2>&1 | tee -a /root/.install-redborder-boot.log
fi

%files
%defattr(0755,root,root)
%{plugins_path}
%defattr(0755,root,root)
%{cookbook_path}
%defattr(0644,root,root)
%{cookbook_path}/README.md

%doc

%changelog
* Fri Oct 22 2021 Javier Rodriguez <javiercrg@redborder.com> - 1.0.2-1
- Netflow pipeline enrichment

* Tue Oct 19 2021 Javier Rodriguez <javiercrg@redborder.com> - 1.0.1-1
- Sflow pipeline enrichment

* Thu Jan 25 2018 Juan J. Prieto <jjprieto@redborder.com> - 1.0.0-1
- first spec version
