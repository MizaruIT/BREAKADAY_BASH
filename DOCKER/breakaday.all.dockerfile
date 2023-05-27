# Author: MizaruIT

FROM debian

ARG TAG="local"
ARG VERSION="local"
ARG BUILD_DATE="n/a"

LABEL org.breakaday.tag="${TAG}"
LABEL org.breakaday.version="${version}"
LABEL org.breakaday.build_date="{BUILD_DATE}"
LABEL org.breakaday.app="breakaday"

# Add files specific to tools used 
ADD breakaday.sh /opt/tools/my_scripts/breakaday.sh


# Add POC / SCANNER
ADD POC /opt/tools/POC
ADD SCANNER /opt/tools/SCANNER
ADD SCANNER_AD /opt/tools/SCANNER_AD

# Add configuration for Docker
ADD DOCKER/sources /root/sources
RUN chmod +x /root/sources/install.sh

# Creation environment
RUN /root/sources/install.sh deploy_breakaday

# Downloading utilities & tools (default)
RUN /root/sources/install.sh package_base
RUN /root/sources/install.sh package_base_breakaday
RUN /root/sources/install.sh package_advanced_ad

# Specific utilities & tools (PENTEST AD)
RUN /root/sources/install.sh package_tools_breakaday

# Specific utilities & tools (GENERAL)
RUN /root/sources/install.sh package_wordlists
RUN /root/sources/install.sh package_cracking
RUN /root/sources/install.sh package_network


RUN /root/sources/install.sh post_install_clean

RUN rm -rf /root/sources

WORKDIR /workspace

ENTRYPOINT [ "/bin/zsh" ]