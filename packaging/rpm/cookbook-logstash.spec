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
if [ -d /var/chef/cookbooks/logstash ]; then
    rm -rf /var/chef/cookbooks/logstash
fi

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

%postun
# Deletes directory when uninstall the package
if [ "$1" = 0 ] && [ -d /var/chef/cookbooks/logstash ]; then
  rm -rf /var/chef/cookbooks/logstash
fi

%files
%defattr(0644,root,root)
%attr(0755,root,root)
%{cookbook_path}
%defattr(0644,root,root)
%{cookbook_path}/README.md

%doc

%changelog
* Thu Oct 10 2024 Miguel Negrón <manegron@redborder.com>
- Add pre and postun

* Thu Jan 19 2023 David Vanhoucke <dvanhoucke@redborder.com>
- Add apstate pipeline

* Fri Sep 22 2023 Miguel Negrón <manegron@redborder.com>
- Remove social

* Tue Apr 18 2023 Luis J. Blanco <ljblanco@redborder.com>
- Monitor pipeline

* Wed Nov 17 2021 Javier Rodriguez <javiercrg@redborder.com>
- Vault pipeline enrichment

* Fri Oct 22 2021 Javier Rodriguez <javiercrg@redborder.com>
- Netflow pipeline enrichment

* Tue Oct 19 2021 Javier Rodriguez <javiercrg@redborder.com>
- Sflow pipeline enrichment

* Thu Jan 25 2018 Juan J. Prieto <jjprieto@redborder.com>
- first spec version
