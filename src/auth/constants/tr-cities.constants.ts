import { BadRequestException } from '@nestjs/common';

export interface TrCity {
  city: string;
  latitude: number;
  longitude: number;
}

export const TR_CITIES: readonly TrCity[] = [
  { city: 'Adana', latitude: 37.0, longitude: 35.3213 },
  { city: 'Adıyaman', latitude: 37.7648, longitude: 38.2786 },
  { city: 'Afyonkarahisar', latitude: 38.7569, longitude: 30.5387 },
  { city: 'Ağrı', latitude: 39.7191, longitude: 43.0503 },
  { city: 'Aksaray', latitude: 38.3687, longitude: 34.037 },
  { city: 'Amasya', latitude: 40.6499, longitude: 35.8353 },
  { city: 'Ankara', latitude: 39.9334, longitude: 32.8597 },
  { city: 'Antalya', latitude: 36.8969, longitude: 30.7133 },
  { city: 'Ardahan', latitude: 41.1105, longitude: 42.7022 },
  { city: 'Artvin', latitude: 41.1828, longitude: 41.8183 },
  { city: 'Aydın', latitude: 37.856, longitude: 27.8416 },
  { city: 'Balıkesir', latitude: 39.6484, longitude: 27.8826 },
  { city: 'Bartın', latitude: 41.6344, longitude: 32.3375 },
  { city: 'Batman', latitude: 37.8812, longitude: 41.1351 },
  { city: 'Bayburt', latitude: 40.2552, longitude: 40.2249 },
  { city: 'Bilecik', latitude: 40.1506, longitude: 29.9833 },
  { city: 'Bingöl', latitude: 38.8854, longitude: 40.4983 },
  { city: 'Bitlis', latitude: 38.4006, longitude: 42.1095 },
  { city: 'Bolu', latitude: 40.7395, longitude: 31.6116 },
  { city: 'Burdur', latitude: 37.7203, longitude: 30.2908 },
  { city: 'Bursa', latitude: 40.1828, longitude: 29.067 },
  { city: 'Çanakkale', latitude: 40.1553, longitude: 26.4142 },
  { city: 'Çankırı', latitude: 40.6013, longitude: 33.6134 },
  { city: 'Çorum', latitude: 40.5506, longitude: 34.9556 },
  { city: 'Denizli', latitude: 37.7765, longitude: 29.0864 },
  { city: 'Diyarbakır', latitude: 37.9144, longitude: 40.2306 },
  { city: 'Düzce', latitude: 40.8438, longitude: 31.1565 },
  { city: 'Edirne', latitude: 41.6772, longitude: 26.5557 },
  { city: 'Elazığ', latitude: 38.6748, longitude: 39.2232 },
  { city: 'Erzincan', latitude: 39.75, longitude: 39.5 },
  { city: 'Erzurum', latitude: 39.9, longitude: 41.27 },
  { city: 'Eskişehir', latitude: 39.7767, longitude: 30.5206 },
  { city: 'Gaziantep', latitude: 37.0662, longitude: 37.3833 },
  { city: 'Giresun', latitude: 40.9128, longitude: 38.3895 },
  { city: 'Gümüşhane', latitude: 40.4603, longitude: 39.4814 },
  { city: 'Hakkâri', latitude: 37.5744, longitude: 43.7408 },
  { city: 'Hatay', latitude: 36.2021, longitude: 36.1606 },
  { city: 'Iğdır', latitude: 39.9237, longitude: 44.045 },
  { city: 'Isparta', latitude: 37.7648, longitude: 30.5566 },
  { city: 'İstanbul', latitude: 41.0082, longitude: 28.9784 },
  { city: 'İzmir', latitude: 38.4192, longitude: 27.1287 },
  { city: 'Kahramanmaraş', latitude: 37.5736, longitude: 36.9371 },
  { city: 'Karabük', latitude: 41.2061, longitude: 32.6204 },
  { city: 'Karaman', latitude: 37.1811, longitude: 33.215 },
  { city: 'Kars', latitude: 40.6013, longitude: 43.0975 },
  { city: 'Kastamonu', latitude: 41.3887, longitude: 33.7827 },
  { city: 'Kayseri', latitude: 38.7312, longitude: 35.4787 },
  { city: 'Kırıkkale', latitude: 39.8468, longitude: 33.5153 },
  { city: 'Kırklareli', latitude: 41.7333, longitude: 27.2167 },
  { city: 'Kırşehir', latitude: 39.1458, longitude: 34.1606 },
  { city: 'Kilis', latitude: 36.7184, longitude: 37.1212 },
  { city: 'Kocaeli', latitude: 40.7654, longitude: 29.9408 },
  { city: 'Konya', latitude: 37.8746, longitude: 32.4932 },
  { city: 'Kütahya', latitude: 39.4242, longitude: 29.9833 },
  { city: 'Malatya', latitude: 38.3554, longitude: 38.3335 },
  { city: 'Manisa', latitude: 38.6191, longitude: 27.4289 },
  { city: 'Mardin', latitude: 37.3212, longitude: 40.7245 },
  { city: 'Mersin', latitude: 36.8121, longitude: 34.6415 },
  { city: 'Muğla', latitude: 37.2153, longitude: 28.3636 },
  { city: 'Muş', latitude: 38.9462, longitude: 41.7539 },
  { city: 'Nevşehir', latitude: 38.6244, longitude: 34.7141 },
  { city: 'Niğde', latitude: 37.9698, longitude: 34.6766 },
  { city: 'Ordu', latitude: 40.9862, longitude: 37.8797 },
  { city: 'Osmaniye', latitude: 37.0742, longitude: 36.2478 },
  { city: 'Rize', latitude: 41.0201, longitude: 40.5234 },
  { city: 'Sakarya', latitude: 40.7569, longitude: 30.3781 },
  { city: 'Samsun', latitude: 41.2867, longitude: 36.33 },
  { city: 'Siirt', latitude: 37.9333, longitude: 41.95 },
  { city: 'Sinop', latitude: 42.0231, longitude: 35.1531 },
  { city: 'Sivas', latitude: 39.7477, longitude: 37.0179 },
  { city: 'Şanlıurfa', latitude: 37.1591, longitude: 38.7969 },
  { city: 'Şırnak', latitude: 37.5164, longitude: 42.4611 },
  { city: 'Tekirdağ', latitude: 40.9833, longitude: 27.5167 },
  { city: 'Tokat', latitude: 40.3167, longitude: 36.55 },
  { city: 'Trabzon', latitude: 41.0027, longitude: 39.7168 },
  { city: 'Tunceli', latitude: 39.1081, longitude: 39.5471 },
  { city: 'Uşak', latitude: 38.6823, longitude: 29.4082 },
  { city: 'Van', latitude: 38.4942, longitude: 43.38 },
  { city: 'Yalova', latitude: 40.655, longitude: 29.2769 },
  { city: 'Yozgat', latitude: 39.8181, longitude: 34.8147 },
  { city: 'Zonguldak', latitude: 41.4564, longitude: 31.7987 },
] as const;

const normalizeTr = (value: string): string =>
  value
    .replace(/İ/g, 'i')
    .replace(/I/g, 'i')
    .replace(/ı/g, 'i')
    .toLowerCase()
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/[^a-z0-9]/g, '');

const CITY_INDEX: ReadonlyMap<string, TrCity> = new Map(
  TR_CITIES.map((c) => [normalizeTr(c.city), c]),
);

export const resolveCityCoordinates = (city: string): { latitude: number; longitude: number } => {
  const match = CITY_INDEX.get(normalizeTr(city ?? ''));
  if (!match) {
    throw new BadRequestException('INVALID_CITY');
  }
  return { latitude: match.latitude, longitude: match.longitude };
};

export const findTrCity = (city: string): TrCity | undefined =>
  CITY_INDEX.get(normalizeTr(city ?? ''));
