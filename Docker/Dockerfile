FROM ubuntu:18.04
ENV PATH="/root/miniconda3/bin:${PATH}"
ARG PATH="/root/miniconda3/bin:${PATH}"
RUN apt-get update
RUN apt-get install -y software-properties-common
RUN apt-get install -y lsb-release && apt-get clean all
RUN apt-get update
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys E298A3A825C0D65DFD57CBB651716619E084DAB9
RUN apt-get update

RUN apt-get install -y wget && rm -rf /var/lib/apt/lists/*
RUN add-apt-repository universe
RUN apt-get update
ENV TZ=Asia
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN date
RUN apt install -y r-base

RUN wget \
    https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh \
    && mkdir /root/.conda \
    && bash Miniconda3-latest-Linux-x86_64.sh -b \
    && rm -f Miniconda3-latest-Linux-x86_64.sh
RUN conda --version

WORKDIR /conda
COPY diff_expr_env.yml /conda/diff_expr_env.yml
RUN conda env create -f /conda/diff_expr_env.yml
RUN apt-get update -y
RUN apt-get install vim -y
RUN apt-get update -y
RUN echo "source activate diffexpr" > ~/.bashrc
ENV PATH /root/miniconda3/envs/diffexpr/bin:$PATH
RUN R -e "install.packages('BiocManager',dependencies=TRUE, repos='http://cran.rstudio.com/')"
RUN R -e "BiocManager::install('edgeR')"
RUN R -e "BiocManager::install('dplyr')"
RUN pip install gunicorn
#RUN python manage.py collectstatic

#docker run -it --env-file /home/ubuntu/yasin/NCC/ncc-backend/env.lst -v /home/ubuntu/yasin/NCC/ncc-backend/:/home/conda/ -p 9798:8000 ncc-backend:0.1 bash
#docker run -it --env-file /home/ubuntu/sohel/ncc-backend/env.lst -v /home/ubuntu/sohel/ncc-backend/:/home/conda/ -p 9799:8000 ncc-backend:0.1 bash

#docker run -it --env-file /home/ubuntu/sohel/ncc-backend/env.lst -v /var/run/docker.sock:/var/run/docker.sock -v /home/ubuntu/sohel/ncc-backend/:/home/conda/ -p 9799:8009 ncc-backend:0.2 bash

#docker run -it --env-file /home/ubuntu/sameer/ncc-backend/env.lst -v /var/run/docker.sock:/var/run/docker.sock -v /home/ubuntu/sameer/ncc-backend/:/home/conda/ -p 9798:8000 ncc-backend:0.2 bash


#  MAIN COMMAND ->     docker run -it --env-file /home/ubuntu/sohel/ncc-backend/env.lst -v /home/ubuntu/:/home/ubuntu/  -v /var/run/docker.sock:/var/run/docker.sock -v /home/ubuntu/sohel/ncc-backend/:/home/conda/ -p 9192:8000 ncc-backend:0.3 bash

