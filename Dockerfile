FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY snark_prover.py /app/
RUN pip install --no-cache-dir flask && mkdir -p /app/security && echo "# placeholder" > /app/security/__init__.py && printf "NORMALIZER_VERSION='1.0'\n\nfrom unicodedata import normalize as uni_normalize\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" > /app/security/normalizer.py

EXPOSE 5001
CMD ["python", "snark_prover.py"]